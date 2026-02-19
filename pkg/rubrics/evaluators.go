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

	EvalContextKey = "evalContext"

	rsaPrefix = "-----BEGIN RSA PRIVATE KEY-----" // #nosec G101 - Not a credential
)

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
		Password     string // #nosec G117 -- Used for testing, not real creds
		DatabaseFile string
		SrcDir       string
		HTTPClient   *http.Client
		JWTParser    func(tokenString string, claims jwt.Claims) (*jwt.Token, error)
	}
)

// EvalContextOption is a functional option for configuring EvalContext
type EvalContextOption func(*EvalContext)

// NewEvalContext creates a new evaluation context with default JWT parser
func NewEvalContext(hostURL string, opts ...EvalContextOption) *EvalContext {
	// Defaults
	ec := &EvalContext{
		HostURL: hostURL,
		HTTPClient: &http.Client{
			Transport: http.DefaultTransport,
			Timeout:   2 * time.Second,
		},
	}
	// Options
	for _, opt := range opts {
		opt(ec)
	}
	// Set default JWT parser if not provided
	if ec.JWTParser == nil {
		ec.JWTParser = defaultJWTParser(ec.HostURL+JWKSEndpoint, keyfunc.Options{
			Client: ec.HTTPClient,
		})
	}

	return ec
}

// WithJWTParser sets a custom JWT parser function
func WithJWTParser(parser func(tokenString string, claims jwt.Claims) (*jwt.Token, error)) EvalContextOption {
	return func(ec *EvalContext) {
		ec.JWTParser = parser
	}
}

func WithHTTPClient(client *http.Client) EvalContextOption {
	return func(ec *EvalContext) {
		ec.HTTPClient = client
	}
}

// WithDatabaseFile sets the database file path
func WithDatabaseFile(file string) EvalContextOption {
	return func(ec *EvalContext) {
		ec.DatabaseFile = file
	}
}

// WithSrcDir sets the source directory path
func WithSrcDir(dir string) EvalContextOption {
	return func(ec *EvalContext) {
		ec.SrcDir = dir
	}
}

// WithUsername sets the username for authentication
func WithUsername(username string) EvalContextOption {
	return func(ec *EvalContext) {
		ec.Username = username
	}
}

// NewRequest creates a new request combining the HostURL and endpoint
func (ec *EvalContext) NewRequest(ctx context.Context, method, endpoint string, body io.Reader) (*http.Request, error) {
	u, err := url.Parse(ec.HostURL)
	if err != nil {
		return nil, err
	}
	u.Path, err = url.JoinPath(u.Path, endpoint)
	if err != nil {
		return nil, err
	}
	// #nosec G704 -- The URL is constructed from the configuration and is intended to be used directly.
	return http.NewRequestWithContext(ctx, method, u.String(), body)
}

func defaultJWTParser(jwksEndpoint string, options keyfunc.Options) func(tokenString string, claims jwt.Claims) (*jwt.Token, error) {
	return func(tokenString string, claims jwt.Claims) (*jwt.Token, error) {
		jwks, err := keyfunc.Get(jwksEndpoint, options)
		if err != nil {
			return nil, err
		}
		return jwt.ParseWithClaims(tokenString, claims, jwks.Keyfunc)
	}
}

// EvaluateValidJWT checks if valid JWT authentication works
func EvaluateValidJWT(_ context.Context, _ baserubrics.ProgramRunner, bag baserubrics.RunBag) baserubrics.RubricItem {
	item := baserubrics.RubricItem{
		Name:   "/auth valid JWT authN",
		Points: 15,
	}

	ec := baserubrics.BagValue[EvalContext](bag, EvalContextKey)
	validJWT, err := authentication(ec, false)
	if err != nil && !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		item.Note = err.Error()
		return item
	}

	ec.ValidJWT = validJWT
	bag["validJWT"] = validJWT
	bag[EvalContextKey] = ec
	item.Awarded = 15
	return item
}

// EvaluateExpiredJWT checks if expired JWT is properly returned
func EvaluateExpiredJWT(_ context.Context, _ baserubrics.ProgramRunner, bag baserubrics.RunBag) baserubrics.RubricItem {
	item := baserubrics.RubricItem{
		Name:   "/auth?expired=true JWT authN (expired)",
		Points: 5,
	}

	ec := baserubrics.BagValue[EvalContext](bag, "evalContext")
	t, err := authentication(ec, true)
	switch {
	case t == nil:
		item.Note = "expected expired JWT to exist"
		return item
	case err == nil:
		item.Note = "expected expired JWT to error"
		return item
	}

	ec.ExpiredJWT = t
	bag["expiredJWT"] = t
	bag["evalContext"] = ec
	item.Awarded = 5

	return item
}

// EvaluateHTTPMethods checks if proper HTTP methods and status codes are used
func EvaluateHTTPMethods(ctx context.Context, _ baserubrics.ProgramRunner, bag baserubrics.RunBag) baserubrics.RubricItem {
	item := baserubrics.RubricItem{
		Name:    "Proper HTTP methods/Status codes",
		Points:  10,
		Awarded: 1, // free point for even math
	}

	ec := baserubrics.BagValue[EvalContext](bag, "evalContext")
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

	client := ec.HTTPClient

	for endpoint, methods := range badMethods {
		for _, method := range methods {
			req, err := ec.NewRequest(ctx, method, endpoint, http.NoBody)
			if err != nil {
				continue
			}
			resp, err := client.Do(req) // #nosec G704
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

	ec := baserubrics.BagValue[EvalContext](bag, "evalContext")
	if ec.ValidJWT == nil {
		item.Note = "no valid JWT found"
		return item
	}

	jwks, err := keyfunc.Get(ec.HostURL+JWKSEndpoint, keyfunc.Options{
		Client: ec.HTTPClient,
	})
	if err != nil {
		item.Note = err.Error()
		return item
	}

	_, err = jwt.ParseWithClaims(ec.ValidJWT.Raw, &jwt.RegisteredClaims{}, jwks.Keyfunc)
	if err != nil {
		item.Note = err.Error()
		req, err2 := ec.NewRequest(context.Background(), http.MethodGet, JWKSEndpoint, http.NoBody)
		if err2 == nil {
			resp, err3 := ec.HTTPClient.Do(req) // #nosec G704
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

	ec := baserubrics.BagValue[EvalContext](bag, "evalContext")
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

	ec := baserubrics.BagValue[EvalContext](bag, "evalContext")
	if ec.ExpiredJWT == nil {
		item.Note = "no expired JWT found"
		return item
	}

	jwks, err := keyfunc.Get(ec.HostURL+JWKSEndpoint, keyfunc.Options{
		Client: ec.HTTPClient,
	})
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
func EvaluateDatabaseExists(ctx context.Context, _ baserubrics.ProgramRunner, bag baserubrics.RunBag) baserubrics.RubricItem {
	item := baserubrics.RubricItem{
		Name:   "Database exists",
		Points: 15,
	}

	ec := baserubrics.BagValue[EvalContext](bag, "evalContext")
	if _, err := os.Stat(ec.DatabaseFile); err != nil {
		item.Note = err.Error()
		return item
	}
	item.Awarded += 5

	// sql.Open does not verify the file exists, and only errors on bad drivers.
	db, _ := sql.Open("sqlite", ec.DatabaseFile)
	defer func() { _ = db.Close() }()

	rows, err := db.QueryContext(ctx, "SELECT * FROM keys")
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

	ec := baserubrics.BagValue[EvalContext](bag, "evalContext")
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

		ec := baserubrics.BagValue[EvalContext](bag, "evalContext")
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

	ec := baserubrics.BagValue[EvalContext](bag, "evalContext")
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
		Password string `json:"password"` // #nosec G117 -- test field
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

	ec := baserubrics.BagValue[EvalContext](bag, "evalContext")
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

	ec := baserubrics.BagValue[EvalContext](bag, "evalContext")
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

		ec := baserubrics.BagValue[EvalContext](bag, "evalContext")

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
		JWT   string `json:"jwt"` // #nosec G117 -- test field
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

	// Parse using the configured parser (verifies in prod, mocks in test)
	return ec.JWTParser(string(body), &jwt.RegisteredClaims{})
}

func authenticatePostJSON(ec *EvalContext, expired bool) (*http.Response, error) {
	var bb bytes.Buffer
	if err := json.NewEncoder(&bb).Encode(struct {
		Username string `json:"username"`
		Password string `json:"password"` // #nosec G117 -- test field
	}{
		Username: Username,
		Password: Password,
	}); err != nil {
		return nil, err
	}
	req, err := ec.NewRequest(context.Background(), http.MethodPost, AuthEndpoint, &bb)
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

	return ec.HTTPClient.Do(req) // #nosec G704
}

func authenticatePostForm(ec *EvalContext, expired bool) (*http.Response, error) {
	data := url.Values{}
	data.Set("username", Username)
	data.Set("password", Password)

	req, err := ec.NewRequest(context.Background(), http.MethodPost, AuthEndpoint, strings.NewReader(data.Encode()))
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

	return ec.HTTPClient.Do(req) // #nosec G704
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
	req, err := ec.NewRequest(context.Background(), http.MethodPost, RegistrationEndpoint, &bb)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Type", "application/json")

	return ec.HTTPClient.Do(req) // #nosec G704
}

func authenticationWithCreds(ec *EvalContext, username, password string) (*http.Response, error) {
	var bb bytes.Buffer
	if err := json.NewEncoder(&bb).Encode(map[string]string{
		"username": username,
		"password": password,
	}); err != nil {
		return nil, err
	}

	req, err := ec.NewRequest(context.Background(), http.MethodPost, AuthEndpoint, &bb)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Type", "application/json")

	resp, err := ec.HTTPClient.Do(req) // #nosec G704
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
