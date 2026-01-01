package rubrics

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite" // SQLite driver

	baserubrics "github.com/jh125486/gradebot/pkg/rubrics"
)

const (
	RegistrationEndpoint = "/register"
	AuthEndpoint         = "/auth"
	JWKSEndpoint         = "/.well-known/jwks.json"
	Username             = "userABC"
	Password             = "password123"

	rsaPrefix = "-----BEGIN RSA PRIVATE KEY-----" // #nosec G101 - Not a credential
	rsaSuffix = "-----END RSA PRIVATE KEY-----"
)

// HTTPClient defines the interface for making HTTP requests
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// parameterizedInsertion matches SQL parameterized insert statements for keys table
var parameterizedInsertion = regexp.MustCompile(
	`(?i)INSERT *(OR *REPLACE *)?INTO *(?-i)keys(?i) *` +
		`(\( *key, *exp *\) *VALUES *\(\?, *\? *\)|` +
		`\( *kid, *key, *exp *\) *VALUES *\(\?, *\?, *\? *\))`,
)

type (
	key struct {
		KID                  int64  `db:"kid"`
		EncipheredPrivateKey []byte `db:"key"`
		Expiration           int64  `db:"exp"`
	}
	user struct {
		ID           int64      `db:"id"`
		Username     string     `db:"username"`
		PasswordHash string     `db:"password_hash"`
		Email        string     `db:"email"`
		RegisteredAt time.Time  `db:"date_registered"`
		LastLoginAt  *time.Time `db:"last_login"`
	}
	authLog struct {
		ID        int64     `db:"id"`
		RequestIP string    `db:"request_ip"`
		RequestTS time.Time `db:"request_timestamp"`
		UserID    int64     `db:"user_id"`
	}
	EvalContext struct {
		HostURL      string
		ValidJWT     *jwt.Token
		ExpiredJWT   *jwt.Token
		Username     string
		Password     string
		DatabaseFile string
		SrcDir       string
		HTTPClient   HTTPClient
	}
)

// GetHTTPClient returns the HTTP client, defaulting to a basic client if not set
func (ec *EvalContext) GetHTTPClient() HTTPClient {
	if ec.HTTPClient == nil {
		return &http.Client{
			Transport: http.DefaultTransport,
			Timeout:   2 * time.Second,
		}
	}
	return ec.HTTPClient
}

// EvaluateValidJWT checks if valid JWT authentication works
func EvaluateValidJWT(_ context.Context, _ baserubrics.ProgramRunner, bag baserubrics.RunBag) baserubrics.RubricItem {
	item := baserubrics.RubricItem{
		Name:   "/auth valid JWT authN",
		Points: 15,
	}

	ec := getEvalContext(bag)
	validJWT, err := authentication(ec, false)
	if err != nil && !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		item.Note = err.Error()
		return item
	}

	ec.ValidJWT = validJWT
	bag["validJWT"] = validJWT
	bag["evalContext"] = ec
	item.Awarded = 15
	return item
}

// EvaluateExpiredJWT checks if expired JWT is properly returned
func EvaluateExpiredJWT(_ context.Context, _ baserubrics.ProgramRunner, bag baserubrics.RunBag) baserubrics.RubricItem {
	item := baserubrics.RubricItem{
		Name:   "/auth?expired=true JWT authN (expired)",
		Points: 5,
	}

	ec := getEvalContext(bag)
	t, err := authentication(ec, true)
	switch {
	case t == nil:
		item.Note = "expected expired JWT to exist"
		return item
	case t.Header == nil:
		item.Note = "expected expired JWT header to exist"
		return item
	case err == nil:
		item.Note = "expected expired JWT to error"
		return item
	case t.Valid:
		item.Note = "expected expired JWT to be invalid"
		return item
	}

	ec.ExpiredJWT = t
	bag["expiredJWT"] = t
	bag["evalContext"] = ec
	item.Awarded = 5
	return item
}

// EvaluateHTTPMethods checks if proper HTTP methods and status codes are used
func EvaluateHTTPMethods(_ context.Context, _ baserubrics.ProgramRunner, bag baserubrics.RunBag) baserubrics.RubricItem {
	item := baserubrics.RubricItem{
		Name:    "Proper HTTP methods/Status codes",
		Points:  10,
		Awarded: 1, // free point for even math
	}

	ec := getEvalContext(bag)
	badMethods := map[string][]string{
		AuthEndpoint: {
			http.MethodGet,
			http.MethodPut,
			http.MethodDelete,
			http.MethodPatch,
			http.MethodHead,
		},
		JWKSEndpoint: {
			http.MethodPost,
			http.MethodPut,
			http.MethodDelete,
			http.MethodPatch,
		},
	}

	client := ec.GetHTTPClient()

	for endpoint, methods := range badMethods {
		for _, method := range methods {
			req, err := http.NewRequestWithContext(context.Background(), method, ec.HostURL+endpoint, http.NoBody)
			if err != nil {
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			if resp.StatusCode == http.StatusMethodNotAllowed {
				item.Awarded++
			}
			_ = resp.Body.Close()
		}
	}

	return item
}

// EvaluateValidJWKInJWKS checks if valid JWK is found in JWKS
func EvaluateValidJWKInJWKS(_ context.Context, _ baserubrics.ProgramRunner, bag baserubrics.RunBag) baserubrics.RubricItem {
	item := baserubrics.RubricItem{
		Name:   "Valid JWK found in JWKS",
		Points: 20,
	}

	ec := getEvalContext(bag)
	if ec.ValidJWT == nil {
		item.Note = "no valid JWT found"
		return item
	}

	jwks, err := keyfunc.Get(ec.HostURL+JWKSEndpoint, keyfunc.Options{})
	if err != nil {
		item.Note = err.Error()
		return item
	}

	_, err = jwt.ParseWithClaims(ec.ValidJWT.Raw, &jwt.RegisteredClaims{}, jwks.Keyfunc)
	if err != nil {
		item.Note = err.Error()
		req, err2 := http.NewRequestWithContext(context.Background(), http.MethodGet, ec.HostURL+JWKSEndpoint, http.NoBody)
		if err2 == nil {
			resp, err3 := ec.GetHTTPClient().Do(req)
			if err3 == nil {
				defer resp.Body.Close()
				b, _ := httputil.DumpResponse(resp, true)
				item.Note = fmt.Sprintf("%s\nJWKS Response:\n%s", item.Note, string(b))
			}
		}
		return item
	}

	item.Awarded = 20
	return item
}

// EvaluateExpiredJWTIsExpired checks if expired JWT has correct expiry
func EvaluateExpiredJWTIsExpired(_ context.Context, _ baserubrics.ProgramRunner, bag baserubrics.RunBag) baserubrics.RubricItem {
	item := baserubrics.RubricItem{
		Name:   "Expired JWT is expired",
		Points: 5,
	}

	ec := getEvalContext(bag)
	if ec.ExpiredJWT == nil {
		item.Note = "no expired JWT found"
		return item
	}

	expiry, err := ec.ExpiredJWT.Claims.GetExpirationTime()
	if err != nil {
		item.Note = err.Error()
		return item
	}
	if expiry == nil {
		item.Note = "expected expired JWT to be returned for query param 'expired=true'"
		return item
	}
	if expiry.After(time.Now()) {
		item.Note = "expected expired token to have an expiry in the past"
		return item
	}

	item.Awarded = 5
	return item
}

// EvaluateExpiredJWKNotInJWKS checks if expired JWK is not in JWKS
func EvaluateExpiredJWKNotInJWKS(_ context.Context, _ baserubrics.ProgramRunner, bag baserubrics.RunBag) baserubrics.RubricItem {
	item := baserubrics.RubricItem{
		Name:   "Expired JWK does not exist in JWKS",
		Points: 10,
	}

	ec := getEvalContext(bag)
	if ec.ExpiredJWT == nil {
		item.Note = "no expired JWT found"
		return item
	}

	jwks, err := keyfunc.Get(ec.HostURL+JWKSEndpoint, keyfunc.Options{})
	if err != nil {
		item.Note = err.Error()
		return item
	}

	_, err = jwt.ParseWithClaims(ec.ExpiredJWT.Raw, &jwt.RegisteredClaims{}, jwks.Keyfunc)
	switch {
	case errors.Is(err, keyfunc.ErrKIDNotFound):
		item.Awarded = 10
	case err != nil:
		item.Note = err.Error()
	default:
		item.Note = "expected KID to not be found"
	}

	return item
}

// EvaluateDatabaseExists checks if database exists with valid and expired keys
func EvaluateDatabaseExists(_ context.Context, _ baserubrics.ProgramRunner, bag baserubrics.RunBag) baserubrics.RubricItem {
	item := baserubrics.RubricItem{
		Name:   "Database exists",
		Points: 15,
	}

	ec := getEvalContext(bag)
	if _, err := os.Stat(ec.DatabaseFile); err != nil {
		item.Note = err.Error()
		return item
	}
	item.Awarded += 5

	db, err := sql.Open("sqlite", ec.DatabaseFile)
	if err != nil {
		item.Note = err.Error()
		return item
	}
	defer func() { _ = db.Close() }()

	rows, err := db.QueryContext(context.Background(), "SELECT * FROM keys")
	if err != nil {
		item.Note = err.Error()
		return item
	}
	defer func() { _ = rows.Close() }()

	var validKey, expiredKey bool
	now := time.Now().UTC()

	for rows.Next() {
		var kid int
		var key string
		var exp int64
		if err := rows.Scan(&kid, &key, &exp); err != nil {
			item.Note = err.Error()
			return item
		}
		expiredAt := time.Unix(exp, 0)
		expired := now.After(expiredAt)

		if !expiredKey && expired {
			expiredKey = true
		} else if !validKey && !expired {
			validKey = true
		}
	}

	if err := rows.Err(); err != nil {
		item.Note = err.Error()
		return item
	}

	if validKey {
		item.Awarded += 5
	} else {
		item.Note = "no valid priv key found in DB"
	}
	if expiredKey {
		item.Awarded += 5
	} else {
		if item.Note != "" {
			item.Note += "; "
		}
		item.Note += "no expired priv key found in DB"
	}

	return item
}

// EvaluateDatabaseQueryUsesParameters checks if SQL queries use parameters
func EvaluateDatabaseQueryUsesParameters(_ context.Context, _ baserubrics.ProgramRunner, bag baserubrics.RunBag) baserubrics.RubricItem {
	item := baserubrics.RubricItem{
		Name:   "Database query uses parameters",
		Points: 15,
	}

	ec := getEvalContext(bag)
	err := fs.WalkDir(os.DirFS(ec.SrcDir), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(filepath.Join(ec.SrcDir, p))
		if err != nil {
			return err
		}
		lines := bytes.Split(b, []byte("\n"))
		if slices.ContainsFunc(lines, parameterizedInsertion.Match) {
			item.Awarded = 15
			return io.EOF
		}
		return nil
	})

	if err != nil && !errors.Is(err, io.EOF) {
		item.Note = err.Error()
	} else if item.Awarded == 0 {
		item.Note = "No source files found with SQL insertion parameters"
	}

	return item
}

// EvaluateTableExists creates an evaluator that checks if a table exists
func EvaluateTableExists(table string, points float64) baserubrics.Evaluator {
	return func(_ context.Context, _ baserubrics.ProgramRunner, bag baserubrics.RunBag) baserubrics.RubricItem {
		item := baserubrics.RubricItem{
			Name:   fmt.Sprintf("Create %s table", table),
			Points: points,
		}

		ec := getEvalContext(bag)
		if _, err := os.Stat(ec.DatabaseFile); err != nil {
			item.Note = err.Error()
			return item
		}

		db, err := sqlx.Connect("sqlite", "file:"+ec.DatabaseFile)
		if err != nil {
			item.Note = err.Error()
			return item
		}
		defer func() { _ = db.Close() }()

		exists, err := tableExists(db, table)
		if exists {
			item.Awarded = points
			return item
		}

		item.Note = table + " table does not exist"
		if err != nil {
			item.Note = err.Error()
		}

		return item
	}
}

// EvaluateRegistrationWorks checks if /register endpoint works
func EvaluateRegistrationWorks(_ context.Context, _ baserubrics.ProgramRunner, bag baserubrics.RunBag) baserubrics.RubricItem {
	item := baserubrics.RubricItem{
		Name:   "/register endpoint",
		Points: 20,
	}

	ec := getEvalContext(bag)
	resp, err := registration(ec, ec.Username)
	if err != nil {
		item.Note = err.Error()
		return item
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		item.Note = fmt.Sprintf("expected status code %d or %d, got %d", http.StatusOK, http.StatusCreated, resp.StatusCode)
		return item
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		item.Note = err.Error()
		return item
	}

	var body struct {
		Password string `json:"password"`
	}
	if err := json.Unmarshal(b, &body); err != nil {
		item.Note = err.Error()
		return item
	}

	if body.Password != "" {
		item.Awarded += 5
	}

	if _, err := uuid.Parse(body.Password); err != nil {
		item.Note = "password is not a valid UUID"
		return item
	}

	u, err := dbGet[user](ec, "users", "username", ec.Username)
	if err != nil {
		item.Note = err.Error()
		return item
	}
	item.Awarded += 5 // user exists

	switch u.PasswordHash {
	case "":
		item.Note = "password hash is empty"
		return item
	case body.Password:
		item.Note = "password hash is same as password"
		return item
	}

	item.Awarded += 10 // password hash is hashed
	ec.Password = body.Password
	bag["evalContext"] = ec

	return item
}

// EvaluatePrivateKeysEncrypted checks if private keys are encrypted in database
func EvaluatePrivateKeysEncrypted(_ context.Context, _ baserubrics.ProgramRunner, bag baserubrics.RunBag) baserubrics.RubricItem {
	item := baserubrics.RubricItem{
		Name:   "Private Keys are encrypted in the database",
		Points: 25,
	}

	ec := getEvalContext(bag)
	keys, err := dbSelect[key](ec, "keys", nil)
	if err != nil {
		item.Note = err.Error()
		return item
	}
	if len(keys) == 0 {
		item.Note = "no keys found in database"
		return item
	}

	for _, k := range keys {
		if bytes.HasPrefix(bytes.TrimSpace(k.EncipheredPrivateKey), []byte(rsaPrefix)) {
			item.Note = fmt.Sprintf("private key %v is not encrypted", k.KID)
			return item
		}
	}

	item.Awarded = 25
	return item
}

// EvaluateAuthLogging checks if auth requests are logged
func EvaluateAuthLogging(_ context.Context, _ baserubrics.ProgramRunner, bag baserubrics.RunBag) baserubrics.RubricItem {
	item := baserubrics.RubricItem{
		Name:   "/auth requests are logged",
		Points: 10,
	}

	ec := getEvalContext(bag)
	resp, err := authenticationWithCreds(ec, ec.Username, ec.Password)
	if err != nil {
		item.Note = err.Error()
		return item
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		item.Note = fmt.Sprintf("expected status code %d, got %d", http.StatusOK, resp.StatusCode)
		return item
	}

	user, err := dbGet[user](ec, "users", "username", ec.Username)
	if err != nil {
		item.Note = err.Error()
		return item
	}

	logs, err := dbSelect[authLog](ec, "auth_logs", map[string]any{"user_id": user.ID})
	if err != nil {
		item.Note = err.Error()
		return item
	}
	if len(logs) == 0 {
		item.Note = "no logs found"
		return item
	}

	item.Awarded += 5 // log exists

	switch {
	case logs[0].RequestIP == "":
		item.Note = "request IP is empty"
	case logs[0].RequestTS.IsZero():
		item.Note = "request timestamp is zero"
	default:
		item.Awarded += 5
	}

	return item
}

// EvaluateRateLimiting creates an evaluator that checks rate limiting
func EvaluateRateLimiting(endpoint string, rps int) baserubrics.Evaluator {
	return func(_ context.Context, _ baserubrics.ProgramRunner, bag baserubrics.RunBag) baserubrics.RubricItem {
		item := baserubrics.RubricItem{
			Name:   endpoint + " is rate-limited (optional)",
			Points: 25,
		}

		ec := getEvalContext(bag)

		// quiesce for a second
		time.Sleep(time.Second)
		ticker := time.NewTicker(time.Second / time.Duration(rps))
		defer ticker.Stop()

		// do requests that should not error
		for i := rps; i > 0; i-- {
			<-ticker.C
			resp, err := authenticationWithCreds(ec, ec.Username, ec.Password)
			if err != nil {
				item.Note = err.Error()
				return item
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				item.Note = fmt.Sprintf("expected status code %d, got %d", http.StatusOK, resp.StatusCode)
				return item
			}
		}

		// should be rate limited now
		resp, err := authenticationWithCreds(ec, ec.Username, ec.Password)
		if err != nil {
			item.Note = err.Error()
			return item
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusTooManyRequests {
			item.Note = fmt.Sprintf("expected status code %d, got %d", http.StatusTooManyRequests, resp.StatusCode)
			return item
		}

		item.Awarded = 25
		return item
	}
}

// Helper functions

func getEvalContext(bag baserubrics.RunBag) *EvalContext {
	if ec, ok := bag["evalContext"].(*EvalContext); ok {
		return ec
	}
	return &EvalContext{}
}

func authentication(ec *EvalContext, expired bool) (*jwt.Token, error) {
	resp, err := authenticatePostForm(ec, expired)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp, err = authenticatePostJSON(ec, expired)
		if err != nil {
			return nil, err
		}
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jsonBody struct {
		JWT   string `json:"jwt"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &jsonBody); err == nil {
		switch {
		case jsonBody.JWT != "":
			return jwt.ParseWithClaims(jsonBody.JWT, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
				return token, nil
			})
		case jsonBody.Token != "":
			return jwt.ParseWithClaims(jsonBody.Token, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
				return token, nil
			})
		}
	}

	if len(strings.Split(string(body), ".")) != 3 {
		return nil, errors.New(`no JWT found in response. Tried raw, JSON["jwt"] and JSON["token"]`)
	}

	return jwt.ParseWithClaims(string(body), &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
		return token, nil
	})
}

func authenticatePostJSON(ec *EvalContext, expired bool) (*http.Response, error) {
	var bb bytes.Buffer
	if err := json.NewEncoder(&bb).Encode(struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{
		Username: Username,
		Password: Password,
	}); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ec.HostURL+AuthEndpoint, &bb)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Type", "application/json")
	if expired {
		q := req.URL.Query()
		q.Add("expired", "true")
		req.URL.RawQuery = q.Encode()
	}

	return ec.GetHTTPClient().Do(req)
}

func authenticatePostForm(ec *EvalContext, expired bool) (*http.Response, error) {
	data := url.Values{}
	data.Set("username", Username)
	data.Set("password", Password)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ec.HostURL+AuthEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(Username, Password)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept-Type", "application/json")
	if expired {
		q := req.URL.Query()
		q.Add("expired", "true")
		req.URL.RawQuery = q.Encode()
	}

	return ec.GetHTTPClient().Do(req)
}

func registration(ec *EvalContext, username string) (*http.Response, error) {
	payload := map[string]string{
		"username": username,
		"email":    username + "@test.com",
	}
	var bb bytes.Buffer
	if err := json.NewEncoder(&bb).Encode(payload); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ec.HostURL+RegistrationEndpoint, &bb)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Type", "application/json")

	return ec.GetHTTPClient().Do(req)
}

func authenticationWithCreds(ec *EvalContext, username, password string) (*http.Response, error) {
	var bb bytes.Buffer
	if err := json.NewEncoder(&bb).Encode(map[string]string{
		"username": username,
		"password": password,
	}); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ec.HostURL+AuthEndpoint, &bb)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Type", "application/json")

	resp, err := ec.GetHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	return resp, nil
}

func tableExists(db *sqlx.DB, tableName string) (bool, error) {
	var name string
	err := db.Get(&name, "SELECT name FROM sqlite_master WHERE type='table' AND name=?", tableName)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func dbGet[T any](ec *EvalContext, table, field string, value any) (*T, error) {
	db, err := sqlx.Connect("sqlite", "file:"+ec.DatabaseFile)
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()

	var t T
	query := fmt.Sprintf(`SELECT * FROM %s WHERE %s=?`, table, field)
	if err := db.Get(&t, query, value); err != nil {
		return nil, err
	}

	return &t, nil
}

func dbSelect[T any](ec *EvalContext, table string, where map[string]any) ([]T, error) {
	db, err := sqlx.Connect("sqlite", "file:"+ec.DatabaseFile)
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()

	keys := make([]string, 0)
	values := make([]any, 0)
	for k, v := range where {
		keys = append(keys, k)
		values = append(values, v)
	}

	var query strings.Builder
	query.WriteString("SELECT * FROM " + table)
	if len(keys) > 0 {
		query.WriteString(" WHERE ")
		for i := range keys {
			if i > 0 && i < len(keys) {
				query.WriteString(" AND ")
			}
			query.WriteString(keys[i] + "=?")
		}
	}

	var t []T
	if err := db.Select(&t, query.String(), values...); err != nil {
		return t, err
	}

	return t, nil
}
