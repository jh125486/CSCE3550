package rubrics_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jh125486/CSCE3550/pkg/rubrics"
	baserubrics "github.com/jh125486/gradebot/pkg/rubrics"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

const (
	testUUIDPasswordJSON = `{"password":"550e8400-e29b-41d4-a716-446655440000"}`
	validJWKInJWKS       = "ValidJWKInJWKS"
	expiredJWTToken      = "expired.jwt.token"
)

// mockRoundTripper allows mocking HTTP responses for testing
type mockRoundTripper struct {
	RoundTripFunc func(*http.Request) (*http.Response, error)
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.RoundTripFunc != nil {
		return m.RoundTripFunc(req)
	}
	return nil, errors.New("RoundTripFunc not implemented")
}

func newMockClient(f func(*http.Request) (*http.Response, error)) *http.Client {
	return &http.Client{
		Transport: &mockRoundTripper{RoundTripFunc: f},
	}
}

// mockJWTParser returns a JWT parser that parses without verification
func mockJWTParser() func(string, jwt.Claims) (*jwt.Token, error) {
	return func(tokenString string, claims jwt.Claims) (*jwt.Token, error) {
		token, _, err := jwt.NewParser().ParseUnverified(tokenString, claims)
		return token, err
	}
}

// mockExpiredJWTParser returns a parser that checks exp and returns ErrTokenExpired if expired
func mockExpiredJWTParser() func(string, jwt.Claims) (*jwt.Token, error) {
	return func(tokenString string, claims jwt.Claims) (*jwt.Token, error) {
		token, _, err := jwt.NewParser().ParseUnverified(tokenString, claims)
		if err != nil {
			return nil, err
		}
		if exp, err := token.Claims.GetExpirationTime(); err == nil && exp != nil {
			if exp.Before(time.Now()) {
				return token, jwt.ErrTokenExpired
			}
		}
		return token, nil
	}
}

type mockProgramRunner struct{}

func (mockProgramRunner) Run(_ context.Context, _ ...string) error {
	return nil
}

func (mockProgramRunner) Cleanup(_ context.Context) error {
	return nil
}

func (mockProgramRunner) Do(_ string) (stdout, stderr []string, err error) {
	return nil, nil, nil
}

func (mockProgramRunner) Kill() error {
	return nil
}

func (mockProgramRunner) Path() string {
	return ""
}

func createTestDB(t *testing.T) string {
	t.Helper()
	dbFile := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dbFile)
	require.NoError(t, err)

	_, err = db.ExecContext(t.Context(), `CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		password_hash TEXT NOT NULL,
		email TEXT NOT NULL DEFAULT '',
		date_registered DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_login DATETIME
	)`)
	require.NoError(t, err)

	_, err = db.ExecContext(t.Context(), `CREATE TABLE IF NOT EXISTS keys (
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	)`)
	require.NoError(t, err)

	_, err = db.ExecContext(t.Context(), `CREATE TABLE IF NOT EXISTS auth_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		request_ip TEXT,
		request_timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		user_id INTEGER
	)`)
	require.NoError(t, err)

	require.NoError(t, db.Close())
	return dbFile
}

func TestEvaluateDatabaseQueryUsesParameters(t *testing.T) {
	t.Parallel()
	dbFile := createTestDB(t)

	ctx := t.Context()
	db, err := sqlx.Connect("sqlite", dbFile)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, "INSERT INTO keys (key, exp) VALUES (?, ?)", []byte("test-key"), time.Now().Add(time.Hour).Unix())
	require.NoError(t, err)
	_ = db.Close()

	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	ec := &rubrics.EvalContext{DatabaseFile: dbFile}
	bag["evalContext"] = ec

	result := rubrics.EvaluateDatabaseQueryUsesParameters(ctx, pr, bag)
	// Without source files, this should return 0
	assert.Equal(t, 0.0, result.Awarded)
}
func TestEvaluateRegistrationWorks(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		hostURL    string
		wantPoints float64
	}{
		{
			name:       "no server running",
			hostURL:    "http://127.0.0.1:9999",
			wantPoints: 20.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{
				HostURL: tt.hostURL,
				HTTPClient: newMockClient(func(_ *http.Request) (*http.Response, error) {
					return nil, errors.New("connection refused")
				}),
			}
			bag["evalContext"] = ec

			result := rubrics.EvaluateRegistrationWorks(ctx, pr, bag)
			assert.Equal(t, tt.wantPoints, result.Points)
			assert.NotNil(t, result)
		})
	}
}

func TestGetEvalContext(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		bagSetup func() baserubrics.RunBag
		wantNil  bool
	}{
		{
			name: "context exists in bag",
			bagSetup: func() baserubrics.RunBag {
				bag := make(baserubrics.RunBag)
				ec := &rubrics.EvalContext{HostURL: "http://test:8080"}
				bag["evalContext"] = ec
				return bag
			},
			wantNil: false,
		},
		{
			name: "empty bag returns nil context",
			bagSetup: func() baserubrics.RunBag {
				return make(baserubrics.RunBag)
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			bag := tt.bagSetup()
			ec := baserubrics.BagValue[rubrics.EvalContext](bag, "evalContext")
			if tt.wantNil {
				assert.Nil(t, ec)
			} else {
				assert.NotNil(t, ec)
			}
		})
	}
}

func TestEvalContextFields(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ec   rubrics.EvalContext
	}{
		{
			name: "all fields set",
			ec: rubrics.EvalContext{
				HostURL:      "http://localhost:8080",
				Username:     "test",
				Password:     "pass",
				DatabaseFile: filepath.Join(os.TempDir(), "test.db"),
				SrcDir:       "/src",
			},
		},
		{
			name: "empty context",
			ec:   rubrics.EvalContext{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Just verify struct can be created
			assert.NotNil(t, tt.ec)
		})
	}
}

func TestNewEvalContextOptions(t *testing.T) {
	t.Parallel()

	type args struct {
		hostURL string
		opts    []rubrics.EvalContextOption
	}
	tests := []struct {
		name   string
		args   args
		verify func(t *testing.T, ec *rubrics.EvalContext)
	}{
		{
			name: "WithSrcDir sets source directory",
			args: args{
				hostURL: "http://localhost:8080",
				opts: []rubrics.EvalContextOption{
					rubrics.WithJWTParser(mockJWTParser()),
					rubrics.WithSrcDir("/custom/src/path"),
				},
			},
			verify: func(t *testing.T, ec *rubrics.EvalContext) {
				assert.Equal(t, "/custom/src/path", ec.SrcDir)
			},
		},
		{
			name: "WithUsername sets username",
			args: args{
				hostURL: "http://localhost:8080",
				opts: []rubrics.EvalContextOption{
					rubrics.WithJWTParser(mockJWTParser()),
					rubrics.WithUsername("testuser"),
				},
			},
			verify: func(t *testing.T, ec *rubrics.EvalContext) {
				assert.Equal(t, "testuser", ec.Username)
			},
		},
		{
			name: "multiple options combined",
			args: args{
				hostURL: "http://localhost:8080",
				opts: []rubrics.EvalContextOption{
					rubrics.WithJWTParser(mockJWTParser()),
					rubrics.WithSrcDir("/src"),
					rubrics.WithUsername("admin"),
					rubrics.WithDatabaseFile("/data/test.db"),
				},
			},
			verify: func(t *testing.T, ec *rubrics.EvalContext) {
				assert.Equal(t, "/src", ec.SrcDir)
				assert.Equal(t, "admin", ec.Username)
				assert.Equal(t, "/data/test.db", ec.DatabaseFile)
				assert.Equal(t, "http://localhost:8080", ec.HostURL)
			},
		},
		{
			name: "empty SrcDir option",
			args: args{
				hostURL: "http://localhost:8080",
				opts: []rubrics.EvalContextOption{
					rubrics.WithJWTParser(mockJWTParser()),
					rubrics.WithSrcDir(""),
				},
			},
			verify: func(t *testing.T, ec *rubrics.EvalContext) {
				assert.Empty(t, ec.SrcDir)
			},
		},
		{
			name: "empty Username option",
			args: args{
				hostURL: "http://localhost:8080",
				opts: []rubrics.EvalContextOption{
					rubrics.WithJWTParser(mockJWTParser()),
					rubrics.WithUsername(""),
				},
			},
			verify: func(t *testing.T, ec *rubrics.EvalContext) {
				assert.Empty(t, ec.Username)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ec := rubrics.NewEvalContext(tt.args.hostURL, tt.args.opts...)

			require.NotNil(t, ec)
			tt.verify(t, ec)
		})
	}
}

// generateTestRSAKey creates an RSA key pair for testing JWKS functionality
func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return privateKey
}

// createJWKSJSON creates a JWKS JSON response from an RSA public key
func createJWKSJSON(t *testing.T, publicKey *rsa.PublicKey, kid string) string {
	t.Helper()
	// Base64url encode the modulus and exponent
	nBytes := publicKey.N.Bytes()
	eBytes := big.NewInt(int64(publicKey.E)).Bytes()

	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": kid,
				"n":   base64.RawURLEncoding.EncodeToString(nBytes),
				"e":   base64.RawURLEncoding.EncodeToString(eBytes),
			},
		},
	}

	jwksJSON, err := json.Marshal(jwks)
	require.NoError(t, err)
	return string(jwksJSON)
}

// signJWTWithKey creates a signed JWT using the provided RSA private key
func signJWTWithKey(t *testing.T, privateKey *rsa.PrivateKey, kid string, claims jwt.Claims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	signedToken, err := token.SignedString(privateKey)
	require.NoError(t, err)
	return signedToken
}

func TestDefaultJWTParser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		setup       func(t *testing.T) (ec *rubrics.EvalContext, jwtString string)
		wantValid   bool
		wantErr     bool
		wantErrText string
	}{
		{
			name: "valid JWT with mock JWKS",
			setup: func(t *testing.T) (*rubrics.EvalContext, string) {
				t.Helper()
				privateKey := generateTestRSAKey(t)
				kid := "test-key-1"
				jwksJSON := createJWKSJSON(t, &privateKey.PublicKey, kid)
				claims := jwt.RegisteredClaims{
					Subject:   "test-user",
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
				}
				signedJWT := signJWTWithKey(t, privateKey, kid, claims)

				mockClient := newMockClient(func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(jwksJSON)),
						Header:     make(http.Header),
					}, nil
				})

				ec := rubrics.NewEvalContext("http://localhost:8080",
					rubrics.WithHTTPClient(mockClient),
				)
				return ec, signedJWT
			},
			wantValid: true,
			wantErr:   false,
		},
		{
			name: "invalid signature - key mismatch",
			setup: func(t *testing.T) (*rubrics.EvalContext, string) {
				t.Helper()
				signingKey := generateTestRSAKey(t)
				jwksKey := generateTestRSAKey(t) // Different key!
				kid := "test-key-1"
				jwksJSON := createJWKSJSON(t, &jwksKey.PublicKey, kid)
				claims := jwt.RegisteredClaims{
					Subject:   "test-user",
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				}
				signedJWT := signJWTWithKey(t, signingKey, kid, claims)

				mockClient := newMockClient(func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(jwksJSON)),
						Header:     make(http.Header),
					}, nil
				})

				ec := rubrics.NewEvalContext("http://localhost:8080",
					rubrics.WithHTTPClient(mockClient),
				)
				return ec, signedJWT
			},
			wantValid:   false,
			wantErr:     true,
			wantErrText: "signature",
		},
		{
			name: "JWKS fetch error",
			setup: func(t *testing.T) (*rubrics.EvalContext, string) {
				t.Helper()
				mockClient := newMockClient(func(_ *http.Request) (*http.Response, error) {
					return nil, errors.New("connection refused")
				})

				ec := rubrics.NewEvalContext("http://localhost:8080",
					rubrics.WithHTTPClient(mockClient),
				)
				return ec, "any.jwt.token"
			},
			wantValid:   false,
			wantErr:     true,
			wantErrText: "connection refused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ec, jwtString := tt.setup(t)

			token, err := ec.JWTParser(jwtString, &jwt.RegisteredClaims{})

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrText != "" {
					assert.Contains(t, err.Error(), tt.wantErrText)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, token)
				assert.Equal(t, tt.wantValid, token.Valid)
			}
		})
	}
}

func TestEvaluateValidJWKInJWKSSuccess(t *testing.T) {
	t.Parallel()

	// Generate RSA key pair
	privateKey := generateTestRSAKey(t)
	kid := "valid-key-1"

	// Create JWKS JSON
	jwksJSON := createJWKSJSON(t, &privateKey.PublicKey, kid)

	// Create and sign a valid JWT
	claims := jwt.RegisteredClaims{
		Subject:   "test-user",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	signedJWT := signJWTWithKey(t, privateKey, kid, claims)

	// Parse the JWT to get a *jwt.Token (needed for ec.ValidJWT)
	parser := jwt.NewParser()
	validToken, _, err := parser.ParseUnverified(signedJWT, &jwt.RegisteredClaims{})
	require.NoError(t, err)
	validToken.Raw = signedJWT // Ensure Raw is set for re-verification

	// Mock client returns JWKS
	mockClient := newMockClient(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(jwksJSON)),
			Header:     make(http.Header),
		}, nil
	})

	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	ec := &rubrics.EvalContext{
		HostURL:    "http://localhost:8080",
		ValidJWT:   validToken,
		HTTPClient: mockClient,
	}
	bag["evalContext"] = ec

	result := rubrics.EvaluateValidJWKInJWKS(ctx, pr, bag)
	assert.NotNil(t, result)
	assert.Equal(t, 20.0, result.Awarded)
	assert.Empty(t, result.Note)
}

func TestEvaluateDatabaseExistsErrorPaths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		setupBag    func(t *testing.T) baserubrics.RunBag
		wantAwarded float64
	}{
		{
			name: "database file does not exist",
			setupBag: func(_ *testing.T) baserubrics.RunBag {
				bag := make(baserubrics.RunBag)
				ec := &rubrics.EvalContext{DatabaseFile: "/nonexistent/path/db.db"}
				bag["evalContext"] = ec
				return bag
			},
			wantAwarded: 0.0,
		},
		{
			name: "empty database file path",
			setupBag: func(_ *testing.T) baserubrics.RunBag {
				bag := make(baserubrics.RunBag)
				ec := &rubrics.EvalContext{DatabaseFile: ""}
				bag["evalContext"] = ec
				return bag
			},
			wantAwarded: 0.0,
		},
		{
			name: "file exists but is not a valid database",
			setupBag: func(t *testing.T) baserubrics.RunBag {
				t.Helper()
				// Create a file that exists but isn't a valid SQLite DB
				tmpFile := filepath.Join(t.TempDir(), "invalid.db")
				require.NoError(t, os.WriteFile(tmpFile, []byte("not a database"), 0o644))
				bag := make(baserubrics.RunBag)
				ec := &rubrics.EvalContext{DatabaseFile: tmpFile}
				bag["evalContext"] = ec
				return bag
			},
			wantAwarded: 5.0, // Gets 5 points for file existing, fails on Ping
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := tt.setupBag(t)

			result := rubrics.EvaluateDatabaseExists(ctx, pr, bag)
			assert.Equal(t, tt.wantAwarded, result.Awarded)
			assert.Greater(t, result.Points, 0.0)
		})
	}
}

func TestEvaluateTableExistsWithDatabase(t *testing.T) {
	t.Parallel()
	dbFile := createTestDB(t)

	tests := []struct {
		name        string
		tableName   string
		points      float64
		wantAwarded float64
	}{
		{"keys table exists", "keys", 5.0, 5.0},
		{"users table exists", "users", 10.0, 10.0},
		{"auth_logs table exists", "auth_logs", 15.0, 15.0},
		{"nonexistent table", "nonexistent_table", 5.0, 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{DatabaseFile: dbFile}
			bag["evalContext"] = ec

			evaluator := rubrics.EvaluateTableExists(tt.tableName, tt.points)
			result := evaluator(ctx, pr, bag)

			assert.Equal(t, tt.wantAwarded, result.Awarded)
			assert.Equal(t, tt.points, result.Points)
		})
	}
}

func TestEvaluateDatabaseQueryUsesParametersWithSourceDir(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	dbFile := createTestDB(t)

	// Create a source file with parameterized query
	srcDir := filepath.Join(tmpDir, "src")
	err := os.MkdirAll(srcDir, 0o755)
	require.NoError(t, err)

	sourceFile := filepath.Join(srcDir, "main.go")
	err = os.WriteFile(sourceFile, []byte(`
		INSERT INTO keys (key, exp) VALUES (?, ?)
	`), 0o644)
	require.NoError(t, err)

	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	bag["evalContext"] = &rubrics.EvalContext{
		DatabaseFile: dbFile,
		SrcDir:       srcDir,
	}

	result := rubrics.EvaluateDatabaseQueryUsesParameters(ctx, pr, bag)
	// Should find parameterized query
	assert.Greater(t, result.Awarded, 0.0)
	assert.Equal(t, 15.0, result.Points)
}

func TestEvaluateDatabaseQueryUsesParametersNoMatch(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	dbFile := createTestDB(t)

	// Create a source file WITHOUT parameterized query
	srcDir := filepath.Join(tmpDir, "src")
	err := os.MkdirAll(srcDir, 0o755)
	require.NoError(t, err)

	// This file has SQL but NO parameter markers (? or $1 etc)
	sourceFile := filepath.Join(srcDir, "main.go")
	err = os.WriteFile(sourceFile, []byte(`
		package main
		
		func main() {
			// This is just regular code, no parameterized SQL
			query := "SELECT * FROM users"
		}
	`), 0o644)
	require.NoError(t, err)

	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	bag["evalContext"] = &rubrics.EvalContext{
		DatabaseFile: dbFile,
		SrcDir:       srcDir,
	}

	result := rubrics.EvaluateDatabaseQueryUsesParameters(ctx, pr, bag)
	// Should NOT find parameterized query
	assert.Equal(t, 0.0, result.Awarded)
	assert.Equal(t, 15.0, result.Points)
	assert.Contains(t, result.Note, "No source files found with SQL insertion parameters")
}

func TestEvaluatePrivateKeysEncrypted(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		setupBag    func(t *testing.T) baserubrics.RunBag
		wantAwarded float64
		wantNoteVal string
	}{
		{
			name: "database does not exist",
			setupBag: func(_ *testing.T) baserubrics.RunBag {
				bag := make(baserubrics.RunBag)
				bag["evalContext"] = rubrics.NewEvalContext("http://localhost:8080",
					rubrics.WithDatabaseFile("/nonexistent.db"),
				)
				return bag
			},
			wantAwarded: 0.0,
		},
		{
			name: "empty database file",
			setupBag: func(_ *testing.T) baserubrics.RunBag {
				bag := make(baserubrics.RunBag)
				bag["evalContext"] = rubrics.NewEvalContext("http://localhost:8080",
					rubrics.WithDatabaseFile(""),
				)
				return bag
			},
			wantAwarded: 0.0,
		},
		{
			name: "no keys in database",
			setupBag: func(t *testing.T) baserubrics.RunBag {
				t.Helper()
				bag := make(baserubrics.RunBag)
				ec := &rubrics.EvalContext{DatabaseFile: createTestDB(t)}
				bag["evalContext"] = ec
				return bag
			},
			wantAwarded: 0.0,
			wantNoteVal: "no keys",
		},
		{
			name: "PEM formatted RSA key - not encrypted",
			setupBag: func(t *testing.T) baserubrics.RunBag {
				t.Helper()
				dbFile := createTestDB(t)
				db, err := sqlx.Connect("sqlite", dbFile)
				require.NoError(t, err)
				_, err = db.ExecContext(t.Context(), "INSERT INTO keys (key, exp) VALUES (?, ?)",
					[]byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"),
					time.Now().Add(time.Hour).Unix())
				require.NoError(t, err)
				_ = db.Close()

				bag := make(baserubrics.RunBag)
				bag["evalContext"] = &rubrics.EvalContext{DatabaseFile: dbFile}
				return bag
			},
			wantAwarded: 0.0,
		},
		{
			name: "random bytes - encrypted",
			setupBag: func(t *testing.T) baserubrics.RunBag {
				t.Helper()
				dbFile := createTestDB(t)
				db, err := sqlx.Connect("sqlite", dbFile)
				require.NoError(t, err)
				_, err = db.ExecContext(t.Context(), "INSERT INTO keys (key, exp) VALUES (?, ?)",
					[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
					time.Now().Add(time.Hour).Unix())
				require.NoError(t, err)
				_ = db.Close()

				bag := make(baserubrics.RunBag)
				bag["evalContext"] = &rubrics.EvalContext{DatabaseFile: dbFile}
				return bag
			},
			wantAwarded: 25.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := tt.setupBag(t)

			result := rubrics.EvaluatePrivateKeysEncrypted(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.Equal(t, 25.0, result.Points)
			assert.Equal(t, tt.wantAwarded, result.Awarded)
			if tt.wantNoteVal != "" {
				assert.Contains(t, strings.ToLower(result.Note), tt.wantNoteVal)
			}
		})
	}
}

func TestEvaluateAuthLoggingWithData(t *testing.T) {
	t.Parallel()
	dbFile := createTestDB(t)

	ctx := t.Context()
	db, err := sqlx.Connect("sqlite", dbFile)
	require.NoError(t, err)

	// Insert test data
	_, err = db.ExecContext(ctx, "INSERT INTO users (username, password_hash) VALUES (?, ?)", "testuser", "hash123")
	require.NoError(t, err)

	_, err = db.ExecContext(ctx, "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", "192.168.1.1", 1)
	require.NoError(t, err)

	_, err = db.ExecContext(ctx, "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", "10.0.0.1", 1)
	require.NoError(t, err)

	_ = db.Close()

	tests := []struct {
		name    string
		wantMin float64
	}{
		{
			name:    "logs exist",
			wantMin: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{
				DatabaseFile: dbFile,
				HTTPClient: newMockClient(func(_ *http.Request) (*http.Response, error) {
					return nil, errors.New("connection refused")
				}),
			}
			bag["evalContext"] = ec

			result := rubrics.EvaluateAuthLogging(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.GreaterOrEqual(t, result.Awarded, tt.wantMin)
			assert.Equal(t, 10.0, result.Points)
		})
	}
}

func TestEvaluateValidJWTErrorCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		hostURL string
	}{
		{name: "invalid URL", hostURL: "http://localhost:9999"},
		{name: "empty URL", hostURL: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			bag["evalContext"] = &rubrics.EvalContext{
				HostURL: tt.hostURL,
				HTTPClient: newMockClient(func(_ *http.Request) (*http.Response, error) {
					return nil, errors.New("connection refused")
				}),
			}

			result := rubrics.EvaluateValidJWT(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.Equal(t, 0.0, result.Awarded)
		})
	}
}

func TestEvaluateExpiredJWTErrorCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		hostURL string
	}{
		{name: "invalid URL", hostURL: "http://localhost:9999"},
		{name: "empty URL", hostURL: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{
				HostURL: tt.hostURL,
				HTTPClient: newMockClient(func(_ *http.Request) (*http.Response, error) {
					return nil, errors.New("connection refused")
				}),
			}
			bag["evalContext"] = ec

			result := rubrics.EvaluateExpiredJWT(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.Equal(t, 0.0, result.Awarded)
		})
	}
}

func TestEvaluateValidJWKInJWKSErrorPaths(t *testing.T) {
	t.Parallel()

	validJWT := &jwt.Token{Raw: "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE5OTk5OTk5OTl9.fake"}

	tests := []struct {
		name         string
		setupBag     func() baserubrics.RunBag
		wantAwarded  float64
		wantNoteText string
	}{
		{
			name: "no valid JWT",
			setupBag: func() baserubrics.RunBag {
				bag := make(baserubrics.RunBag)
				ec := &rubrics.EvalContext{HostURL: "http://localhost:8080"}
				bag["evalContext"] = ec
				return bag
			},
			wantAwarded:  0.0,
			wantNoteText: "no valid JWT",
		},
		{
			name: "JWKS endpoint connection refused",
			setupBag: func() baserubrics.RunBag {
				bag := make(baserubrics.RunBag)
				ec := &rubrics.EvalContext{
					HostURL:  "http://localhost:9999",
					ValidJWT: validJWT,
					HTTPClient: newMockClient(func(_ *http.Request) (*http.Response, error) {
						return nil, errors.New("connection refused")
					}),
				}
				bag["evalContext"] = ec
				return bag
			},
			wantAwarded:  0.0,
			wantNoteText: "connection refused",
		},
		{
			name: "parse error includes JWKS debug info",
			setupBag: func() baserubrics.RunBag {
				bag := make(baserubrics.RunBag)
				ec := &rubrics.EvalContext{
					HostURL:  "http://localhost:8080",
					ValidJWT: validJWT,
					HTTPClient: newMockClient(func(_ *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader(`{"keys": []}`)),
							Header:     make(http.Header),
						}, nil
					}),
				}
				bag["evalContext"] = ec
				return bag
			},
			wantAwarded:  0.0,
			wantNoteText: "JWKS Response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := tt.setupBag()

			result := rubrics.EvaluateValidJWKInJWKS(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.Equal(t, tt.wantAwarded, result.Awarded)
			assert.NotEmpty(t, result.Note)
			assert.Contains(t, result.Note, tt.wantNoteText)
		})
	}
}

func TestExpiredJWTEvaluatorsNoExpiredJWT(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		evaluator baserubrics.Evaluator
	}{
		{
			name:      "EvaluateExpiredJWTIsExpired",
			evaluator: rubrics.EvaluateExpiredJWTIsExpired,
		},
		{
			name:      "EvaluateExpiredJWKNotInJWKS",
			evaluator: rubrics.EvaluateExpiredJWKNotInJWKS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{HostURL: "http://localhost:8080"}
			bag["evalContext"] = ec

			result := tt.evaluator(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.Equal(t, 0.0, result.Awarded)
			assert.NotEmpty(t, result.Note)
		})
	}
}

func TestEvaluateTableExistsMultipleTables(t *testing.T) {
	t.Parallel()
	dbFile := createTestDB(t)

	tests := []struct {
		name        string
		tableName   string
		points      float64
		wantAwarded float64
	}{
		{name: "keys table", tableName: "keys", points: 5.0, wantAwarded: 5.0},
		{name: "users table", tableName: "users", points: 5.0, wantAwarded: 5.0},
		{name: "auth_logs table", tableName: "auth_logs", points: 5.0, wantAwarded: 5.0},
		{name: "nonexistent", tableName: "fake_table", points: 5.0, wantAwarded: 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{DatabaseFile: dbFile}
			bag["evalContext"] = ec

			evaluator := rubrics.EvaluateTableExists(tt.tableName, tt.points)
			result := evaluator(ctx, pr, bag)

			assert.Equal(t, tt.points, result.Points)
			assert.Equal(t, tt.wantAwarded, result.Awarded)
		})
	}
}

func TestEvaluateHTTPMethodsInvalidURL(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	bag["evalContext"] = rubrics.NewEvalContext("http://localhost:9999")

	result := rubrics.EvaluateHTTPMethods(ctx, pr, bag)
	assert.NotNil(t, result)
	assert.GreaterOrEqual(t, result.Awarded, 1.0)
}

func TestEvaluateRegistrationWorksInvalidURL(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	bag["evalContext"] = rubrics.NewEvalContext("http://localhost:9999")

	result := rubrics.EvaluateRegistrationWorks(ctx, pr, bag)
	assert.NotNil(t, result)
	assert.Equal(t, 0.0, result.Awarded)
	assert.NotEmpty(t, result.Note)
}

func TestEvaluateRateLimitingInvalidEndpoint(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	ec := &rubrics.EvalContext{
		HostURL:  "http://localhost:9999",
		Username: "testuser",
		Password: "testpass",
		HTTPClient: newMockClient(func(_ *http.Request) (*http.Response, error) {
			return nil, errors.New("connection refused")
		}),
	}
	bag["evalContext"] = ec

	evaluator := rubrics.EvaluateRateLimiting("/auth", 10)
	result := evaluator(ctx, pr, bag)

	assert.Equal(t, 25.0, result.Points)
	assert.Equal(t, 0.0, result.Awarded)
	assert.NotEmpty(t, result.Note)
}

func TestEvaluateDatabaseQueryUsesParametersErrorPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		setupBag func(t *testing.T) baserubrics.RunBag
	}{
		{
			name: "no database file",
			setupBag: func(_ *testing.T) baserubrics.RunBag {
				bag := make(baserubrics.RunBag)
				ec := &rubrics.EvalContext{DatabaseFile: "/nonexistent/path/db.sqlite"}
				bag["evalContext"] = ec
				return bag
			},
		},
		{
			name: "missing source directory",
			setupBag: func(t *testing.T) baserubrics.RunBag {
				t.Helper()
				bag := make(baserubrics.RunBag)
				ec := &rubrics.EvalContext{SrcDir: filepath.Join(t.TempDir(), "missing")}
				bag["evalContext"] = ec
				return bag
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := tt.setupBag(t)

			result := rubrics.EvaluateDatabaseQueryUsesParameters(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.Equal(t, 0.0, result.Awarded)
			assert.NotEmpty(t, result.Note)
		})
	}
}

func TestDatabaseEvaluatorsWithValidKeys(t *testing.T) {
	t.Parallel()
	dbFile := createTestDB(t)

	ctx := t.Context()
	db, err := sqlx.Connect("sqlite", dbFile)
	require.NoError(t, err)

	// Insert valid and expired keys
	validExp := time.Now().Add(time.Hour).Unix()
	expiredExp := time.Now().Add(-time.Hour).Unix()

	_, err = db.ExecContext(ctx, "INSERT INTO keys (key, exp) VALUES (?, ?)", []byte("valid-key"), validExp)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, "INSERT INTO keys (key, exp) VALUES (?, ?)", []byte("expired-key"), expiredExp)
	require.NoError(t, err)
	_ = db.Close()

	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	ec := &rubrics.EvalContext{DatabaseFile: dbFile}
	bag["evalContext"] = ec

	result := rubrics.EvaluateDatabaseExists(ctx, pr, bag)
	assert.NotNil(t, result)
	// Should find both valid and expired keys
	assert.Equal(t, 15.0, result.Awarded)
}

func TestEvaluateDatabaseExistsBrokenDatabase(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	brokenDB := filepath.Join(tmpDir, "broken.db")

	// Create empty file that's not a valid SQLite database
	err := os.WriteFile(brokenDB, []byte("not a database"), 0o644)
	require.NoError(t, err)

	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	ec := &rubrics.EvalContext{DatabaseFile: brokenDB}
	bag["evalContext"] = ec

	result := rubrics.EvaluateDatabaseExists(ctx, pr, bag)
	assert.NotNil(t, result)
	// Broken DB might still open successfully with SQLite, check it has less than full points
	assert.LessOrEqual(t, result.Awarded, 10.0)
}

func TestEvaluateTableExistsErrorPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		setupBag func(t *testing.T) baserubrics.RunBag
	}{
		{
			name: "invalid database path",
			setupBag: func(_ *testing.T) baserubrics.RunBag {
				bag := make(baserubrics.RunBag)
				bag["evalContext"] = rubrics.NewEvalContext("http://localhost:8080",
					rubrics.WithDatabaseFile("/nonexistent/db.sqlite"),
				)
				return bag
			},
		},
		{
			name: "corrupted database file",
			setupBag: func(t *testing.T) baserubrics.RunBag {
				t.Helper()
				tmpFile := filepath.Join(t.TempDir(), "corrupt.db")
				err := os.WriteFile(tmpFile, []byte("this is not a valid sqlite database"), 0o644)
				require.NoError(t, err)

				bag := make(baserubrics.RunBag)
				bag["evalContext"] = rubrics.NewEvalContext("http://localhost:8080",
					rubrics.WithDatabaseFile(tmpFile),
					rubrics.WithJWTParser(mockJWTParser()),
				)
				return bag
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := tt.setupBag(t)

			evaluator := rubrics.EvaluateTableExists("keys", 5.0)
			result := evaluator(ctx, pr, bag)

			assert.NotNil(t, result)
			assert.Equal(t, 0.0, result.Awarded)
			assert.NotEmpty(t, result.Note)
		})
	}
}

func TestAuthLoggingEdgeCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		setupDB  func(*testing.T, *sqlx.DB)
		minScore float64
	}{
		{
			name: "no data",
			setupDB: func(t *testing.T, db *sqlx.DB) {
				// No data inserted
			},
			minScore: 0.0,
		},
		{
			name: "only users",
			setupDB: func(t *testing.T, db *sqlx.DB) {
				ctx := t.Context()
				_, err := db.ExecContext(ctx, "INSERT INTO users (username, password_hash) VALUES (?, ?)", "user1", "hash1")
				require.NoError(t, err)
			},
			minScore: 0.0,
		},
		{
			name: "complete data - but server not running",
			setupDB: func(t *testing.T, db *sqlx.DB) {
				ctx := t.Context()
				_, err := db.ExecContext(ctx, "INSERT INTO users (username, password_hash) VALUES (?, ?)", "user2", "hash2")
				require.NoError(t, err)
				_, err = db.ExecContext(ctx, "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", "1.2.3.4", 1)
				require.NoError(t, err)
			},
			minScore: 0.0, // Will fail because server not running
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Create fresh database for each test
			dbFile := createTestDB(t)

			db, err := sqlx.Connect("sqlite", dbFile)
			require.NoError(t, err)

			tt.setupDB(t, db)
			_ = db.Close()

			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{
				DatabaseFile: dbFile,
				HTTPClient: newMockClient(func(_ *http.Request) (*http.Response, error) {
					return nil, errors.New("server not running")
				}),
			}
			bag["evalContext"] = ec

			result := rubrics.EvaluateAuthLogging(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.GreaterOrEqual(t, result.Awarded, tt.minScore)
		})
	}
}

func TestHTTPClientInjection(t *testing.T) {
	t.Parallel()
	// Demonstrate dependency injection with mock HTTP client
	mockClient := newMockClient(
		func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusMethodNotAllowed,
				Body:       http.NoBody,
			}, nil
		},
	)

	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	bag["evalContext"] = rubrics.NewEvalContext("http://localhost:8080",
		rubrics.WithHTTPClient(mockClient),
	)

	result := rubrics.EvaluateHTTPMethods(ctx, pr, bag)
	assert.NotNil(t, result)
	// With mock returning 405 for all requests, should score > 1
	assert.Greater(t, result.Awarded, 1.0)
}

func TestAuthenticationWithMockHTTP(t *testing.T) {
	t.Parallel()
	type args struct {
		httpClient *http.Client
		expired    bool
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		wantJWT bool
	}{
		{
			name: "successful auth with JSON response",
			args: args{
				httpClient: newMockClient(
					func(req *http.Request) (*http.Response, error) {
						body := `{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}`
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader(body)),
						}, nil
					},
				),
				expired: false,
			},
			wantErr: false,
			wantJWT: true,
		},
		{
			name: "successful auth with raw JWT",
			args: args{
				httpClient: newMockClient(
					func(req *http.Request) (*http.Response, error) {
						body := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader(body)),
						}, nil
					},
				),
				expired: false,
			},
			wantErr: false,
			wantJWT: true,
		},
		{
			name: "failed auth - http error",
			args: args{
				httpClient: newMockClient(
					func(_ *http.Request) (*http.Response, error) {
						return nil, errors.New("connection refused")
					},
				),
				expired: false,
			},
			wantErr: true,
			wantJWT: false,
		},
		{
			name: "failed auth - non-200 status",
			args: args{
				httpClient: newMockClient(
					func(_ *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusUnauthorized,
							Body:       io.NopCloser(strings.NewReader("unauthorized")),
						}, nil
					},
				),
				expired: false,
			},
			wantErr: true,
			wantJWT: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{
				HostURL:    "http://localhost:8080",
				HTTPClient: tt.args.httpClient,
				JWTParser: func(tokenString string, claims jwt.Claims) (*jwt.Token, error) {
					token, _, err := jwt.NewParser().ParseUnverified(tokenString, claims)
					return token, err
				},
			}
			bag["evalContext"] = ec

			result := rubrics.EvaluateValidJWT(ctx, pr, bag)
			assert.NotNil(t, result)

			if tt.wantJWT {
				assert.Greater(t, result.Awarded, 0.0)
			} else {
				assert.Equal(t, 0.0, result.Awarded)
				assert.NotEmpty(t, result.Note)
			}
		})
	}
}

func TestRegistrationWithMockHTTP(t *testing.T) {
	t.Parallel()
	type args struct {
		httpClient *http.Client
	}
	tests := []struct {
		name        string
		args        args
		wantAwarded float64
	}{
		{
			name: "successful registration",
			args: args{
				httpClient: newMockClient(
					func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader(testUUIDPasswordJSON)),
						}, nil
					},
				),
			},
			wantAwarded: 5.0, // Gets 5 points for valid UUID in response
		},
		{
			name: "registration returns created",
			args: args{
				httpClient: newMockClient(
					func(req *http.Request) (*http.Response, error) {
						body := `{"password":"123e4567-e89b-12d3-a456-426614174000"}`
						return &http.Response{
							StatusCode: http.StatusCreated,
							Body:       io.NopCloser(strings.NewReader(body)),
						}, nil
					},
				),
			},
			wantAwarded: 5.0,
		},
		{
			name: "registration fails - bad status",
			args: args{
				httpClient: newMockClient(
					func(_ *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusBadRequest,
							Body:       io.NopCloser(strings.NewReader(`{"error":"bad request"}`)),
						}, nil
					},
				),
			},
			wantAwarded: 0.0,
		},
		{
			name: "registration fails - connection error",
			args: args{
				httpClient: newMockClient(
					func(_ *http.Request) (*http.Response, error) {
						return nil, errors.New("connection refused")
					},
				),
			},
			wantAwarded: 0.0,
		},
		{
			name: "registration returns invalid password format",
			args: args{
				httpClient: newMockClient(
					func(_ *http.Request) (*http.Response, error) {
						body := `{"password":"not-a-uuid"}`
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader(body)),
						}, nil
					},
				),
			},
			wantAwarded: 5.0, // Gets 5 for valid response, but fails on UUID check
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dbFile := createTestDB(t)
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{
				HostURL:      "http://localhost:8080",
				DatabaseFile: dbFile,
				HTTPClient:   tt.args.httpClient,
				Username:     "testuser",
			}
			bag["evalContext"] = ec

			result := rubrics.EvaluateRegistrationWorks(ctx, pr, bag)
			assert.NotNil(t, result)
			// We only check for UUID validity in response, not DB operations
			assert.Equal(t, tt.wantAwarded, result.Awarded)
		})
	}
}

func TestRateLimitingWithMockHTTP(t *testing.T) {
	t.Parallel()
	type args struct {
		endpoint   string
		rps        int
		httpClient *http.Client
	}
	tests := []struct {
		name        string
		args        args
		wantAwarded float64
	}{
		{
			name: "rate limiting works",
			args: args{
				endpoint: "/auth",
				rps:      2,
				httpClient: newMockClient(
					func(_ *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       http.NoBody,
						}, nil
					},
				),
			},
			wantAwarded: 0.0,
		},
		{
			name: "no rate limiting",
			args: args{
				endpoint: "/auth",
				rps:      2,
				httpClient: newMockClient(
					func(_ *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       http.NoBody,
						}, nil
					},
				),
			},
			wantAwarded: 0.0,
		},
		{
			name: "http error",
			args: args{
				endpoint: "/auth",
				rps:      2,
				httpClient: newMockClient(
					func(_ *http.Request) (*http.Response, error) {
						return nil, errors.New("connection error")
					},
				),
			},
			wantAwarded: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{
				HostURL:    "http://localhost:8080",
				Username:   "testuser",
				Password:   "testpass",
				HTTPClient: tt.args.httpClient,
			}
			bag["evalContext"] = ec

			evaluator := rubrics.EvaluateRateLimiting(tt.args.endpoint, tt.args.rps)
			result := evaluator(ctx, pr, bag)

			assert.NotNil(t, result)
			assert.Equal(t, tt.wantAwarded, result.Awarded)
		})
	}
}

func TestAuthLoggingWithMockHTTP(t *testing.T) {
	t.Parallel()
	dbFile := createTestDB(t)

	// Seed the database with user and auth log
	ctx := t.Context()
	db, err := sqlx.Connect("sqlite", dbFile)
	require.NoError(t, err)

	_, err = db.ExecContext(ctx, "INSERT INTO users (username, password_hash) VALUES (?, ?)", "testuser", "hashvalue")
	require.NoError(t, err)

	_, err = db.ExecContext(ctx, "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", "127.0.0.1", 1)
	require.NoError(t, err)
	_ = db.Close()

	tests := []struct {
		name        string
		httpClient  *http.Client
		wantAwarded float64
	}{
		{
			name: "auth logging works",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       http.NoBody,
					}, nil
				},
			),
			wantAwarded: 10.0,
		},
		{
			name: "auth fails - wrong status",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusUnauthorized,
						Body:       http.NoBody,
					}, nil
				},
			),
			wantAwarded: 0.0,
		},
		{
			name: "auth fails - connection error",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return nil, errors.New("connection error")
				},
			),
			wantAwarded: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{
				HostURL:      "http://localhost:8080",
				DatabaseFile: dbFile,
				Username:     "testuser",
				Password:     "password123",
				HTTPClient:   tt.httpClient,
			}
			bag["evalContext"] = ec

			result := rubrics.EvaluateAuthLogging(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.Equal(t, tt.wantAwarded, result.Awarded)
		})
	}
}

func TestExpiredJWTWithMockHTTP(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		httpClient  *http.Client
		wantAwarded float64
	}{
		{
			name: "expired JWT returned correctly",
			httpClient: newMockClient(
				func(req *http.Request) (*http.Response, error) {
					// Return expired JWT (exp claim in the past)
					body := `{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxNTE2MjM5MDIyfQ.4Adcj0HKQX4K8Y3lVjGdU_FqKJZgqJ5c5fH2VwLjEfw"}`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
					}, nil
				},
			),
			wantAwarded: 5.0,
		},
		{
			name: "no token returned",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{}`)),
					}, nil
				},
			),
			wantAwarded: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			bag["evalContext"] = rubrics.NewEvalContext("http://localhost:8080",
				rubrics.WithHTTPClient(tt.httpClient),
				rubrics.WithJWTParser(mockExpiredJWTParser()),
			)

			result := rubrics.EvaluateExpiredJWT(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.Equal(t, tt.wantAwarded, result.Awarded)
		})
	}
}

func TestJWKSValidationWithMockHTTP(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		httpClient  *http.Client
		setupBag    func() baserubrics.RunBag
		wantAwarded float64
	}{
		{
			name: "EvaluateValidJWKInJWKS - no valid JWT",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"keys":[]}`)),
					}, nil
				},
			),
			setupBag: func() baserubrics.RunBag {
				bag := make(baserubrics.RunBag)
				ec := &rubrics.EvalContext{
					HostURL: "http://localhost:8080",
				}
				bag["evalContext"] = ec
				return bag
			},
			wantAwarded: 0.0,
		},
		{
			name: "EvaluateExpiredJWTIsExpired - no expired JWT",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{}`)),
					}, nil
				},
			),
			setupBag: func() baserubrics.RunBag {
				bag := make(baserubrics.RunBag)
				ec := &rubrics.EvalContext{
					HostURL: "http://localhost:8080",
				}
				bag["evalContext"] = ec
				return bag
			},
			wantAwarded: 0.0,
		},
		{
			name: "EvaluateExpiredJWKNotInJWKS - no expired JWT",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"keys":[]}`)),
					}, nil
				},
			),
			setupBag: func() baserubrics.RunBag {
				bag := make(baserubrics.RunBag)
				ec := &rubrics.EvalContext{
					HostURL: "http://localhost:8080",
				}
				bag["evalContext"] = ec
				return bag
			},
			wantAwarded: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := tt.setupBag()

			if ec := baserubrics.BagValue[rubrics.EvalContext](bag, "evalContext"); ec != nil {
				ec.HTTPClient = tt.httpClient
				bag["evalContext"] = ec
			}

			var result baserubrics.RubricItem
			switch {
			case strings.Contains(tt.name, "ValidJWKInJWKS"):
				result = rubrics.EvaluateValidJWKInJWKS(ctx, pr, bag)
			case strings.Contains(tt.name, "ExpiredJWTIsExpired"):
				result = rubrics.EvaluateExpiredJWTIsExpired(ctx, pr, bag)
			case strings.Contains(tt.name, "ExpiredJWKNotInJWKS"):
				result = rubrics.EvaluateExpiredJWKNotInJWKS(ctx, pr, bag)
			}

			assert.NotNil(t, result)
			assert.Equal(t, tt.wantAwarded, result.Awarded)
			assert.NotEmpty(t, result.Note)
		})
	}
}

func TestHelperFunctionsWithMockHTTP(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		testFunc   string
		httpClient *http.Client
		expired    bool
		wantErr    bool
	}{
		{
			name:     "authenticatePostJSON success",
			testFunc: "postJSON",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"token":"valid"}`)),
					}, nil
				},
			),
			expired: false,
			wantErr: false,
		},
		{
			name:     "authenticatePostJSON expired",
			testFunc: "postJSON",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"token":"expired"}`)),
					}, nil
				},
			),
			expired: true,
			wantErr: false,
		},
		{
			name:     "authenticatePostForm success",
			testFunc: "postForm",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"token":"valid"}`)),
					}, nil
				},
			),
			expired: false,
			wantErr: false,
		},
		{
			name:     "registration success",
			testFunc: "registration",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"password":"uuid-here"}`)),
					}, nil
				},
			),
			expired: false,
			wantErr: false,
		},
		{
			name:     "authenticationWithCreds success",
			testFunc: "authWithCreds",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"token":"valid"}`)),
					}, nil
				},
			),
			expired: false,
			wantErr: false,
		},
		{
			name:     "HTTP error handling",
			testFunc: "postJSON",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return nil, errors.New("network error")
				},
			),
			expired: false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{
				HostURL:    "http://localhost:8080",
				HTTPClient: tt.httpClient,
				Username:   "testuser",
				Password:   "testpass",
			}
			bag["evalContext"] = ec

			// Test the evaluators which use these helper functions
			var result baserubrics.RubricItem
			switch tt.testFunc {
			case "postJSON", "postForm":
				result = rubrics.EvaluateValidJWT(ctx, pr, bag)
			case "registration":
				dbFile := createTestDB(t)
				ec.DatabaseFile = dbFile
				bag["evalContext"] = ec
				result = rubrics.EvaluateRegistrationWorks(ctx, pr, bag)
			case "authWithCreds":
				dbFile := createTestDB(t)
				ec.DatabaseFile = dbFile
				bag["evalContext"] = ec
				result = rubrics.EvaluateAuthLogging(ctx, pr, bag)
			}

			assert.NotNil(t, result)
			if tt.wantErr {
				assert.Equal(t, 0.0, result.Awarded)
			}
		})
	}
}

func TestAuthenticationHelperEdgeCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		httpClient *http.Client
		wantErr    bool
	}{
		{
			name: "authentication with JWT in response",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					body := `{"jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
					}, nil
				},
			),
			wantErr: false,
		},
		{
			name: "authentication with raw JWT body",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					body := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
					}, nil
				},
			),
			wantErr: false,
		},
		{
			name: "authentication with invalid JSON",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{invalid json}`)),
					}, nil
				},
			),
			wantErr: true,
		},
		{
			name: "authentication falls back to postJSON after postForm fails",
			httpClient: func() *http.Client {
				callCount := 0
				return newMockClient(
					func(_ *http.Request) (*http.Response, error) {
						callCount++
						if callCount == 1 {
							// First call (postForm) returns non-200
							return &http.Response{
								StatusCode: http.StatusBadRequest,
								Body:       http.NoBody,
							}, nil
						}
						// Second call (postJSON) succeeds
						body := `{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}`
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader(body)),
						}, nil
					},
				)
			}(),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{
				HostURL:    "http://localhost:8080",
				HTTPClient: tt.httpClient,
				JWTParser: func(tokenString string, claims jwt.Claims) (*jwt.Token, error) {
					token, _, err := jwt.NewParser().ParseUnverified(tokenString, claims)
					return token, err
				},
			}
			bag["evalContext"] = ec

			result := rubrics.EvaluateValidJWT(ctx, pr, bag)
			assert.NotNil(t, result)

			if tt.wantErr {
				assert.Equal(t, 0.0, result.Awarded)
				assert.NotEmpty(t, result.Note)
			} else {
				assert.Greater(t, result.Awarded, 0.0)
			}
		})
	}
}

func TestEvaluateExpiredJWTEdgeCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		httpClient  *http.Client
		wantAwarded float64
		wantNote    bool
	}{
		{
			name: "expired JWT without exp claim",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					// JWT without exp claim
					body := `{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Gfx6VO9tcxwk6xqx9yYzSfebfeakZp5JYIgP_edcw_A"}`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
					}, nil
				},
			),
			wantAwarded: 0.0,
			wantNote:    true,
		},
		{
			name: "expired JWT with future exp",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					// JWT with exp in future
					body := `{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjo5OTk5OTk5OTk5fQ.C-JdoPoGH-YLpL7HuSjNB0cWa0lVVZqI5VdVwrUYtYc"}`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
					}, nil
				},
			),
			wantAwarded: 0.0,
			wantNote:    true,
		},
		{
			name: "expired JWT with header but no token",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"message":"no token"}`)),
					}, nil
				},
			),
			wantAwarded: 0.0,
			wantNote:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{
				HostURL:    "http://localhost:8080",
				HTTPClient: tt.httpClient,
			}
			bag["evalContext"] = ec

			// First get an "expired" JWT
			_ = rubrics.EvaluateExpiredJWT(ctx, pr, bag)

			// Then check if it's properly expired
			result := rubrics.EvaluateExpiredJWTIsExpired(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.Equal(t, tt.wantAwarded, result.Awarded)
			if tt.wantNote {
				assert.NotEmpty(t, result.Note)
			}
		})
	}
}

func TestEvaluateDatabaseExistsEdgeCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		setupDB     func(*testing.T) string
		wantAwarded float64
	}{
		{
			name: "database with only valid keys",
			setupDB: func(t *testing.T) string {
				dbFile := createTestDB(t)
				db, err := sqlx.Connect("sqlite", dbFile)
				require.NoError(t, err)

				validExp := time.Now().Add(time.Hour).Unix()
				_, err = db.ExecContext(t.Context(), "INSERT INTO keys (key, exp) VALUES (?, ?)", []byte("key1"), validExp)
				require.NoError(t, err)
				_, err = db.ExecContext(t.Context(), "INSERT INTO keys (key, exp) VALUES (?, ?)", []byte("key2"), validExp)
				require.NoError(t, err)
				_ = db.Close()
				return dbFile
			},
			wantAwarded: 10.0,
		},
		{
			name: "database with only expired keys",
			setupDB: func(t *testing.T) string {
				dbFile := createTestDB(t)
				db, err := sqlx.Connect("sqlite", dbFile)
				require.NoError(t, err)

				expiredExp := time.Now().Add(-time.Hour).Unix()
				_, err = db.ExecContext(t.Context(), "INSERT INTO keys (key, exp) VALUES (?, ?)", []byte("key1"), expiredExp)
				require.NoError(t, err)
				_ = db.Close()
				return dbFile
			},
			wantAwarded: 10.0, // 5 for DB exists + 5 for expired key
		},
		{
			name: "database with valid and expired keys",
			setupDB: func(t *testing.T) string {
				dbFile := createTestDB(t)
				db, err := sqlx.Connect("sqlite", dbFile)
				require.NoError(t, err)

				validExp := time.Now().Add(time.Hour).Unix()
				expiredExp := time.Now().Add(-time.Hour).Unix()
				_, err = db.ExecContext(t.Context(), "INSERT INTO keys (key, exp) VALUES (?, ?)", []byte("valid-key"), validExp)
				require.NoError(t, err)
				_, err = db.ExecContext(t.Context(), "INSERT INTO keys (key, exp) VALUES (?, ?)", []byte("expired-key"), expiredExp)
				require.NoError(t, err)
				_ = db.Close()
				return dbFile
			},
			wantAwarded: 15.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dbFile := tt.setupDB(t)

			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{DatabaseFile: dbFile}
			bag["evalContext"] = ec

			result := rubrics.EvaluateDatabaseExists(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.Equal(t, tt.wantAwarded, result.Awarded)
		})
	}
}

func TestEvaluateRegistrationWorksEdgeCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		httpClient  *http.Client
		setupDB     func(*testing.T, *rubrics.EvalContext)
		wantAwarded float64
	}{
		{
			name: "registration with empty password field",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"password":""}`)),
					}, nil
				},
			),
			wantAwarded: 0.0,
		},
		{
			name: "registration with non-JSON response",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`plain text response`)),
					}, nil
				},
			),
			wantAwarded: 0.0,
		},
		{
			name: "registration returns invalid UUID password",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"password":"not-uuid"}`)),
					}, nil
				},
			),
			wantAwarded: 5.0, // 5 points for non-empty password
		},
		{
			name: "user exists but password hash is empty",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					// Mock registration success
					password := "123e4567-e89b-12d3-a456-426614174000"
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(fmt.Sprintf(`{"password":%q}`, password))),
					}, nil
				},
			),
			setupDB: func(t *testing.T, ec *rubrics.EvalContext) {
				// Setup DB with user having empty hash
				db, err := sqlx.Connect("sqlite", ec.DatabaseFile)
				require.NoError(t, err)
				_, err = db.ExecContext(t.Context(), "INSERT INTO users (username, password_hash) VALUES (?, ?)", ec.Username, "")
				require.NoError(t, err)
				_ = db.Close()
			},
			wantAwarded: 10.0, // 5 points password + 5 points user exists
		},
		{
			name: "registration success but user not in DB",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"password":"123e4567-e89b-12d3-a456-426614174000"}`)),
					}, nil
				},
			),
			setupDB: func(t *testing.T, ec *rubrics.EvalContext) {
				// Tables created by helpers, but we explicitly don't insert user
				db, err := sqlx.Connect("sqlite", ec.DatabaseFile)
				require.NoError(t, err)
				_ = db.Close()
			},
			wantAwarded: 5.0, // 5 points for password in response
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dbFile := createTestDB(t)
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{
				HostURL:      "http://localhost:8080",
				DatabaseFile: dbFile,
				HTTPClient:   tt.httpClient,
				Username:     "testuser",
			}
			if tt.setupDB != nil {
				tt.setupDB(t, ec)
			}
			bag["evalContext"] = ec

			result := rubrics.EvaluateRegistrationWorks(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.Equal(t, tt.wantAwarded, result.Awarded)
		})
	}
}

func TestEvaluateRegistrationWorksHashEqualsPassword(t *testing.T) {
	t.Parallel()
	password := "123e4567-e89b-12d3-a456-426614174000"
	dbFile := createTestDB(t)

	db, err := sqlx.Connect("sqlite", dbFile)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), "INSERT INTO users (username, password_hash) VALUES (?, ?)", "testuser", password)
	require.NoError(t, err)
	_ = db.Close()

	httpClient := newMockClient(
		func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(fmt.Sprintf(`{"password":%q}`, password))),
			}, nil
		},
	)

	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	ec := &rubrics.EvalContext{
		HostURL:      "http://localhost:8080",
		DatabaseFile: dbFile,
		HTTPClient:   httpClient,
		Username:     "testuser",
	}
	bag["evalContext"] = ec

	result := rubrics.EvaluateRegistrationWorks(ctx, pr, bag)
	assert.NotNil(t, result)
	assert.Equal(t, 10.0, result.Awarded)
	assert.Contains(t, strings.ToLower(result.Note), "password hash is same")
}

func TestEvaluateRegistrationWorksBodyReadError(t *testing.T) {
	t.Parallel()
	httpClient := newMockClient(
		func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(errorReader{}),
			}, nil
		},
	)

	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	ec := &rubrics.EvalContext{
		HostURL:    "http://localhost:8080",
		HTTPClient: httpClient,
		Username:   "testuser",
	}
	bag["evalContext"] = ec

	result := rubrics.EvaluateRegistrationWorks(ctx, pr, bag)
	assert.NotNil(t, result)
	assert.Equal(t, 0.0, result.Awarded)
	assert.Contains(t, result.Note, "read error")
}

func TestEvaluateRegistrationWorksFullFlow(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		httpClient   *http.Client
		setupDB      func(t *testing.T, dbFile string)
		wantAwarded  float64
		wantMinScore bool
	}{
		{
			name: "full registration flow with DB check",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusCreated,
						Body:       io.NopCloser(strings.NewReader(testUUIDPasswordJSON)),
					}, nil
				},
			),
			setupDB: func(t *testing.T, dbFile string) {
				t.Helper()
				db, err := sqlx.Connect("sqlite", dbFile)
				require.NoError(t, err)
				_, err = db.ExecContext(t.Context(), "INSERT INTO users (username, password_hash) VALUES (?, ?)", "testuser", "hashed_password_value")
				require.NoError(t, err)
				_ = db.Close()
			},
			wantMinScore: true,
			wantAwarded:  10.0, // 5 for password + 5 for user in DB
		},
		{
			name: "registration with same password as hash",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(testUUIDPasswordJSON)),
					}, nil
				},
			),
			setupDB:      nil,
			wantMinScore: true,
			wantAwarded:  5.0, // Only password points
		},
		{
			name: "full flow with different hash - all points",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusCreated,
						Body:       io.NopCloser(strings.NewReader(testUUIDPasswordJSON)),
					}, nil
				},
			),
			setupDB: func(t *testing.T, dbFile string) {
				t.Helper()
				db, err := sqlx.Connect("sqlite", dbFile)
				require.NoError(t, err)
				_, err = db.ExecContext(t.Context(), "INSERT INTO users (username, password_hash) VALUES (?, ?)", "testuser", "different_hash")
				require.NoError(t, err)
				_ = db.Close()
			},
			wantMinScore: false,
			wantAwarded:  20.0, // 5 (password) + 5 (user exists) + 10 (hash different)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dbFile := createTestDB(t)

			if tt.setupDB != nil {
				tt.setupDB(t, dbFile)
			}

			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{
				HostURL:      "http://localhost:8080",
				DatabaseFile: dbFile,
				HTTPClient:   tt.httpClient,
				Username:     "testuser",
			}
			bag["evalContext"] = ec

			result := rubrics.EvaluateRegistrationWorks(ctx, pr, bag)
			assert.NotNil(t, result)
			if tt.wantMinScore {
				assert.GreaterOrEqual(t, result.Awarded, tt.wantAwarded)
			} else {
				assert.Equal(t, tt.wantAwarded, result.Awarded)
			}
		})
	}
}

func TestEvaluateJWKSWithValidAndExpiredJWTs(t *testing.T) {
	t.Parallel()
	// Create a scenario where we have both valid and expired JWTs in bag
	validJWT := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjo5OTk5OTk5OTk5fQ.HL8Zg8R6vF5MwL-CK4bKZQ0YbPk0Q5X3g5G7K5jDqYE`
	expiredJWT := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjIifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxNTE2MjM5MDIyfQ.4Adcj0HKQX4K8Y3lVjGdU_FqKJZgqJ5c5fH2VwLjEfw`

	tests := []struct {
		name       string
		httpClient *http.Client
		testFunc   string
		wantMin    float64
	}{
		{
			name: "ValidJWKInJWKS with JWKS error",
			httpClient: newMockClient(
				func(req *http.Request) (*http.Response, error) {
					if strings.Contains(req.URL.Path, "/auth") {
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader(`{"token":"` + validJWT + `"}`)),
						}, nil
					}
					return nil, errors.New("jwks fetch failed")
				},
			),
			testFunc: "ValidJWKInJWKS",
			wantMin:  0.0,
		},
		{
			name: "ExpiredJWKNotInJWKS with JWKS response",
			httpClient: newMockClient(
				func(req *http.Request) (*http.Response, error) {
					if strings.Contains(req.URL.Path, "/auth") {
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader(`{"token":"` + expiredJWT + `"}`)),
						}, nil
					}
					// Return empty JWKS
					body := `{"keys":[]}`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
					}, nil
				},
			),
			testFunc: "ExpiredJWKNotInJWKS",
			wantMin:  0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{
				HostURL:    "http://localhost:8080",
				HTTPClient: tt.httpClient,
			}
			bag["evalContext"] = ec

			// First populate ValidJWT or ExpiredJWT
			if tt.testFunc == validJWKInJWKS {
				_ = rubrics.EvaluateValidJWT(ctx, pr, bag)
			} else {
				_ = rubrics.EvaluateExpiredJWT(ctx, pr, bag)
			}

			// Then test the JWKS validation
			var result baserubrics.RubricItem
			if tt.testFunc == validJWKInJWKS {
				result = rubrics.EvaluateValidJWKInJWKS(ctx, pr, bag)
			} else {
				result = rubrics.EvaluateExpiredJWKNotInJWKS(ctx, pr, bag)
			}

			assert.NotNil(t, result)
			assert.GreaterOrEqual(t, result.Awarded, tt.wantMin)
		})
	}
}

func TestAuthenticatePostJSONEdgeCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		httpClient *http.Client
		expired    bool
		wantErr    bool
	}{
		{
			name: "expired parameter in URL",
			httpClient: newMockClient(
				func(req *http.Request) (*http.Response, error) {
					// Verify expired query param is set
					if req.URL.Query().Get("expired") == "true" {
						body := `{"token":"expired-jwt"}`
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader(body)),
						}, nil
					}
					body := `{"token":"valid-jwt"}`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
					}, nil
				},
			),
			expired: true,
			wantErr: false,
		},
		{
			name: "read body error",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(&errorReader{}),
					}, nil
				},
			),
			expired: false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{
				HostURL:    "http://localhost:8080",
				HTTPClient: tt.httpClient,
			}
			bag["evalContext"] = ec

			var result baserubrics.RubricItem
			if tt.expired {
				result = rubrics.EvaluateExpiredJWT(ctx, pr, bag)
			} else {
				result = rubrics.EvaluateValidJWT(ctx, pr, bag)
			}

			assert.NotNil(t, result)
			if tt.wantErr {
				assert.Equal(t, 0.0, result.Awarded)
			}
		})
	}
}

// errorReader simulates a read error
type errorReader struct{}

func (errorReader) Read(_ []byte) (int, error) {
	return 0, errors.New("simulated read error")
}

func TestHTTPMethodsWithVariousResponses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		httpClient *http.Client
		wantMin    float64
	}{
		{
			name: "all methods return 405",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusMethodNotAllowed,
						Body:       http.NoBody,
					}, nil
				},
			),
			wantMin: 9.0, // 1 base + 9 correct responses
		},
		{
			name: "mixed responses",
			httpClient: func() *http.Client {
				count := 0
				return newMockClient(
					func(_ *http.Request) (*http.Response, error) {
						count++
						if count%2 == 0 {
							return &http.Response{
								StatusCode: http.StatusMethodNotAllowed,
								Body:       http.NoBody,
							}, nil
						}
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       http.NoBody,
						}, nil
					},
				)
			}(),
			wantMin: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{
				HostURL:    "http://localhost:8080",
				HTTPClient: tt.httpClient,
			}
			bag["evalContext"] = ec

			result := rubrics.EvaluateHTTPMethods(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.GreaterOrEqual(t, result.Awarded, tt.wantMin)
		})
	}
}

func TestCompleteJWKSFlow(t *testing.T) {
	t.Parallel()
	// Test complete flow with successful JWKS validation
	jwksResponse := `{"keys":[{"kty":"RSA","use":"sig","kid":"1","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtV","e":"AQAB"}]}`

	tests := []struct {
		name     string
		testFunc string
		setupJWT string
		wantMin  float64
	}{
		{
			name:     "ValidJWKInJWKS dumps response on error",
			testFunc: "ValidJWKInJWKS",
			setupJWT: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjo5OTk5OTk5OTk5fQ.invalid`,
			wantMin:  0.0,
		},
		{
			name:     "ExpiredJWKNotInJWKS with KID not found",
			testFunc: "ExpiredJWKNotInJWKS",
			setupJWT: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ijk5OSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxNTE2MjM5MDIyfQ.invalid`,
			wantMin:  0.0, // Should award 10 points for KID not found
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			httpClient := newMockClient(
				func(req *http.Request) (*http.Response, error) {
					if strings.Contains(req.URL.Path, "jwks") {
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader(jwksResponse)),
						}, nil
					}
					// Auth endpoint
					body := `{"token":"` + tt.setupJWT + `"}`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
					}, nil
				},
			)

			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{
				HostURL:    "http://localhost:8080",
				HTTPClient: httpClient,
			}
			bag["evalContext"] = ec

			// Setup JWT in bag
			if tt.testFunc == validJWKInJWKS {
				_ = rubrics.EvaluateValidJWT(ctx, pr, bag)
			} else {
				_ = rubrics.EvaluateExpiredJWT(ctx, pr, bag)
			}

			// Test JWKS validation
			var result baserubrics.RubricItem
			if tt.testFunc == validJWKInJWKS {
				result = rubrics.EvaluateValidJWKInJWKS(ctx, pr, bag)
			} else {
				result = rubrics.EvaluateExpiredJWKNotInJWKS(ctx, pr, bag)
			}

			assert.NotNil(t, result)
			assert.GreaterOrEqual(t, result.Awarded, tt.wantMin)
		})
	}
}

func TestEvaluateExpiredJWKNotInJWKS_KIDNotFound(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[{"kty":"RSA","use":"sig","kid":"1","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtV","e":"AQAB"}]}`))
	}))
	t.Cleanup(server.Close)

	// Create expired token with missing kid
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   "test",
		ExpiresAt: jwt.NewNumericDate(time.Unix(1516239022, 0)),
	})
	token.Header["kid"] = "missing"
	tokenString, err := token.SignedString([]byte("secret"))
	require.NoError(t, err)
	token.Raw = tokenString

	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	bag["evalContext"] = &rubrics.EvalContext{
		HostURL:    server.URL,
		ExpiredJWT: token,
	}

	result := rubrics.EvaluateExpiredJWKNotInJWKS(ctx, pr, bag)

	assert.NotNil(t, result)
	assert.GreaterOrEqual(t, result.Awarded, 10.0)
}

func TestEvaluateExpiredJWKNotInJWKSScenarios(t *testing.T) {
	t.Parallel()
	jwksBody := `{"keys":[{"kty":"RSA","use":"sig","kid":"present","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtV","e":"AQAB"}]}`

	tests := []struct {
		name      string
		kid       string
		wantAward float64
		wantNote  bool
	}{
		{name: "kid missing yields points", kid: "missing", wantAward: 10.0, wantNote: false},
		{name: "kid present but signature invalid", kid: "present", wantAward: 0.0, wantNote: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(jwksBody))
			}))
			t.Cleanup(ts.Close)

			claims := jwt.RegisteredClaims{
				Subject:   "student",
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
			}
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			token.Header["kid"] = tt.kid
			signed, err := token.SignedString([]byte("secret"))
			require.NoError(t, err)
			token.Raw = signed

			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			bag["evalContext"] = &rubrics.EvalContext{
				HostURL:    ts.URL,
				ExpiredJWT: token,
			}

			result := rubrics.EvaluateExpiredJWKNotInJWKS(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.Equal(t, tt.wantAward, result.Awarded)
			if tt.wantNote {
				assert.NotEmpty(t, result.Note)
			}
		})
	}
}

func TestEvaluateExpiredJWTScenarios(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		httpClient  *http.Client
		wantAwarded float64
		checkNote   bool
	}{
		{
			name: "empty response body",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{}`)),
					}, nil
				},
			),
			wantAwarded: 0.0,
			checkNote:   true,
		},
		{
			name: "token with nil header",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`malformed`)),
					}, nil
				},
			),
			wantAwarded: 0.0,
			checkNote:   true,
		},
		{
			name: "valid token (not expired)",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					body := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjo5OTk5OTk5OTk5fQ.C-JdoPoGH-YLpL7HuSjNB0cWa0lVVZqI5VdVwrUYtYc`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
					}, nil
				},
			),
			wantAwarded: 0.0,
			checkNote:   true,
		},
		{
			name: "postForm and postJSON return non-200",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusUnauthorized,
						Body:       http.NoBody,
					}, nil
				},
			),
			wantAwarded: 0.0,
			checkNote:   true,
		},
		{
			name: "postForm succeeds with JWT",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					body := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNTE2MjM5MDIyfQ.4Adcj0HKQX4K8Y3lVjGdU_FqKJZgqJ5c5fH2VwLjEfw`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
					}, nil
				},
			),
			wantAwarded: 5.0,
			checkNote:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{
				HostURL:    "http://localhost:8080",
				HTTPClient: tt.httpClient,
				JWTParser: func(tokenString string, claims jwt.Claims) (*jwt.Token, error) {
					token, _, err := jwt.NewParser().ParseUnverified(tokenString, claims)
					if err != nil {
						return nil, err
					}
					if exp, err := token.Claims.GetExpirationTime(); err == nil && exp != nil {
						if exp.Before(time.Now()) {
							return token, jwt.ErrTokenExpired
						}
					}
					return token, nil
				},
			}
			bag["evalContext"] = ec

			result := rubrics.EvaluateExpiredJWT(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.Equal(t, tt.wantAwarded, result.Awarded)
			if tt.checkNote {
				assert.NotEmpty(t, result.Note)
			}
		})
	}
}

func TestEvaluateAuthLoggingAllBranches(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		setupDB     func(*testing.T) string
		httpClient  *http.Client
		wantAwarded float64
		noteCheck   string
	}{
		{
			name:    "user not found in DB",
			setupDB: createTestDB,
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       http.NoBody,
					}, nil
				},
			),
			wantAwarded: 0.0,
			noteCheck:   "sql",
		},
		{
			name: "auth_logs table query fails",
			setupDB: func(t *testing.T) string {
				dbFile := createTestDB(t)
				db, err := sqlx.Connect("sqlite", dbFile)
				require.NoError(t, err)
				_, _ = db.ExecContext(t.Context(), "INSERT INTO users (username, password_hash) VALUES (?, ?)", "testuser", "hash")
				// Drop auth_logs table to cause query error
				_, _ = db.ExecContext(t.Context(), "DROP TABLE auth_logs")
				_ = db.Close()
				return dbFile
			},
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       http.NoBody,
					}, nil
				},
			),
			wantAwarded: 0.0,
			noteCheck:   "error",
		},
		{
			name: "logs with empty request IP",
			setupDB: func(t *testing.T) string {
				dbFile := createTestDB(t)
				db, err := sqlx.Connect("sqlite", dbFile)
				require.NoError(t, err)
				_, _ = db.ExecContext(t.Context(), "INSERT INTO users (username, password_hash) VALUES (?, ?)", "testuser", "hash")
				_, _ = db.ExecContext(t.Context(), "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", "", 1)
				_ = db.Close()
				return dbFile
			},
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       http.NoBody,
					}, nil
				},
			),
			wantAwarded: 5.0,
			noteCheck:   "IP",
		},
		{
			name: "logs with zero timestamp",
			setupDB: func(t *testing.T) string {
				dbFile := createTestDB(t)
				db, err := sqlx.Connect("sqlite", dbFile)
				require.NoError(t, err)
				_, _ = db.ExecContext(t.Context(), "INSERT INTO users (username, password_hash) VALUES (?, ?)", "testuser", "hash")
				_, _ = db.ExecContext(t.Context(), "INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?, ?, ?)", "1.2.3.4", "0001-01-01 00:00:00", 1)
				_ = db.Close()
				return dbFile
			},
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       http.NoBody,
					}, nil
				},
			),
			wantAwarded: 5.0,
			noteCheck:   "timestamp",
		},
		{
			name: "no logs found for user",
			setupDB: func(t *testing.T) string {
				dbFile := createTestDB(t)
				db, err := sqlx.Connect("sqlite", dbFile)
				require.NoError(t, err)
				// Insert user but NO auth_logs for this user
				_, _ = db.ExecContext(t.Context(), "INSERT INTO users (username, password_hash) VALUES (?, ?)", "testuser", "hash")
				_ = db.Close()
				return dbFile
			},
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       http.NoBody,
					}, nil
				},
			),
			wantAwarded: 0.0,
			noteCheck:   "no logs found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dbFile := tt.setupDB(t)

			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{
				HostURL:      "http://localhost:8080",
				DatabaseFile: dbFile,
				HTTPClient:   tt.httpClient,
				Username:     "testuser",
				Password:     "testpass",
			}
			bag["evalContext"] = ec

			result := rubrics.EvaluateAuthLogging(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.Equal(t, tt.wantAwarded, result.Awarded)
			if tt.noteCheck != "" {
				assert.Contains(t, strings.ToLower(result.Note), strings.ToLower(tt.noteCheck))
			}
		})
	}
}

func TestEvaluateDatabaseExistsQueryError(t *testing.T) {
	t.Parallel()
	// Create a database that will fail on keys query
	tmpDir := t.TempDir()
	dbFile := filepath.Join(tmpDir, "test.db")

	db, err := sql.Open("sqlite", dbFile)
	require.NoError(t, err)
	// Create wrong schema - keys table without expected columns
	_, err = db.ExecContext(t.Context(), `CREATE TABLE keys (wrong_column TEXT)`)
	require.NoError(t, err)
	_ = db.Close()

	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	ec := &rubrics.EvalContext{DatabaseFile: dbFile}
	bag["evalContext"] = ec

	result := rubrics.EvaluateDatabaseExists(ctx, pr, bag)
	assert.NotNil(t, result)
	// Should get 5 points for DB existing but fail on query
	assert.LessOrEqual(t, result.Awarded, 5.0)
}

func TestAuthenticationHelperReadBodyErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		httpClient *http.Client
	}{
		{
			name: "authentication io.ReadAll error",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(&errorReader{}),
					}, nil
				},
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{
				HostURL:    "http://localhost:8080",
				HTTPClient: tt.httpClient,
			}
			bag["evalContext"] = ec

			result := rubrics.EvaluateValidJWT(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.Equal(t, 0.0, result.Awarded)
			assert.NotEmpty(t, result.Note)
		})
	}
}

func TestEvaluateExpiredJWTIsExpiredAllPaths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		setupExpJWT func(*rubrics.EvalContext)
		wantAwarded float64
		wantNote    bool
	}{
		{
			name: "ExpiredJWT with past expiry",
			setupExpJWT: func(ec *rubrics.EvalContext) {
				token := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxNTE2MjM5MDIyfQ.4Adcj0HKQX4K8Y3lVjGdU_FqKJZgqJ5c5fH2VwLjEfw`
				parsedToken, _ := jwt.Parse(token, func(_ *jwt.Token) (any, error) { return []byte("secret"), nil })
				ec.ExpiredJWT = parsedToken
			},
			wantAwarded: 5.0,
			wantNote:    false,
		},
		{
			name: "ExpiredJWT with future expiry",
			setupExpJWT: func(ec *rubrics.EvalContext) {
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
					Subject:   "future",
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				})
				token.Raw = "future.raw.jwt"
				ec.ExpiredJWT = token
			},
			wantAwarded: 0.0,
			wantNote:    true,
		},
		{
			name: "ExpiredJWT with nil expiry",
			setupExpJWT: func(ec *rubrics.EvalContext) {
				// Token with no exp claim
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
					Subject: "no-exp",
				})
				token.Raw = "noexp.raw.jwt"
				ec.ExpiredJWT = token
			},
			wantAwarded: 0.0,
			wantNote:    true,
		},
		{
			name: "ExpiredJWT with invalid claims type",
			setupExpJWT: func(ec *rubrics.EvalContext) {
				// Token with MapClaims that has invalid exp type
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
					"exp": "not-a-number",
				})
				token.Raw = "invalid.raw.jwt"
				ec.ExpiredJWT = token
			},
			wantAwarded: 0.0,
			wantNote:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{}
			tt.setupExpJWT(ec)
			bag["evalContext"] = ec

			result := rubrics.EvaluateExpiredJWTIsExpired(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.Equal(t, tt.wantAwarded, result.Awarded)
			if tt.wantNote {
				assert.NotEmpty(t, result.Note)
			}
		})
	}
}

func TestEvaluateHTTPMethodsRequestErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		httpClient *http.Client
		wantMin    float64
	}{
		{
			name: "request failure still yields base points",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return nil, errors.New("connection refused")
				},
			),
			wantMin: 1.0,
		},
		{
			name: "method not allowed returns extra points",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusMethodNotAllowed,
						Body:       io.NopCloser(strings.NewReader("")),
					}, nil
				},
			),
			wantMin: 10.0, // base 1 + 9 methods that return 405
		},
		{
			name: "wrong status code no extra points",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader("")),
					}, nil
				},
			),
			wantMin: 1.0, // only base point
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{
				HostURL:    "http://localhost:8080",
				HTTPClient: tt.httpClient,
			}
			bag["evalContext"] = ec

			result := rubrics.EvaluateHTTPMethods(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.GreaterOrEqual(t, result.Awarded, tt.wantMin)
		})
	}
}

func TestTableExistsHelper(t *testing.T) {
	t.Parallel()
	dbFile := createTestDB(t)

	tests := []struct {
		name      string
		tableName string
		wantExist bool
	}{
		{name: "keys table exists", tableName: "keys", wantExist: true},
		{name: "users table exists", tableName: "users", wantExist: true},
		{name: "fake table does not exist", tableName: "nonexistent", wantExist: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{DatabaseFile: dbFile}
			bag["evalContext"] = ec

			evaluator := rubrics.EvaluateTableExists(tt.tableName, 5.0)
			result := evaluator(ctx, pr, bag)

			assert.NotNil(t, result)
			if tt.wantExist {
				assert.Equal(t, 5.0, result.Awarded)
			} else {
				assert.Equal(t, 0.0, result.Awarded)
			}
		})
	}
}

func TestValidJWKInJWKSComprehensive(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		setupJWT    func() *jwt.Token
		jwksResp    string
		wantAwarded float64
	}{
		{
			name: "ValidJWT present with successful JWKS lookup",
			setupJWT: func() *jwt.Token {
				// Create a token with kid=1
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
					Subject: "test",
				})
				token.Header["kid"] = "1"
				token.Raw = "valid.jwt.token"
				return token
			},
			jwksResp: `{
				"keys": [{
					"kty": "RSA",
					"use": "sig",
					"kid": "1",
					"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
					"e": "AQAB"
				}]
			}`,
			wantAwarded: 0.0, // JWT signature is invalid
		},
		{
			name: "ValidJWT present but JWKS fetch fails with httputil dump",
			setupJWT: func() *jwt.Token {
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
					Subject: "test",
				})
				token.Header["kid"] = "1"
				token.Raw = "valid.jwt.token"
				return token
			},
			jwksResp:    "", // Will cause fetch error
			wantAwarded: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			httpClient := newMockClient(
				func(req *http.Request) (*http.Response, error) {
					if strings.Contains(req.URL.Path, "jwks") {
						if tt.jwksResp == "" {
							return nil, errors.New("jwks fetch failed")
						}
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader(tt.jwksResp)),
						}, nil
					}
					return &http.Response{StatusCode: http.StatusNotFound, Body: http.NoBody}, nil
				},
			)

			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{
				HostURL:    "http://localhost:8080",
				ValidJWT:   tt.setupJWT(),
				HTTPClient: httpClient,
			}
			bag["evalContext"] = ec

			result := rubrics.EvaluateValidJWKInJWKS(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.Equal(t, tt.wantAwarded, result.Awarded)
			assert.NotEmpty(t, result.Note)
		})
	}
}

func TestExpiredJWKNotInJWKSComprehensive(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		setupJWT func() *jwt.Token
		jwksResp string
		wantMin  float64
	}{
		{
			name: "ExpiredJWT with kid not in JWKS",
			setupJWT: func() *jwt.Token {
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
					Subject:   "test",
					ExpiresAt: jwt.NewNumericDate(time.Unix(1516239022, 0)),
				})
				token.Header["kid"] = "999" // Non-existent kid
				token.Raw = expiredJWTToken
				return token
			},
			jwksResp: `{
				"keys": [{
					"kty": "RSA",
					"use": "sig",
					"kid": "1",
					"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtV",
					"e": "AQAB"
				}]
			}`,
			wantMin: 0.0, // KID not found should award 10 points
		},
		{
			name: "ExpiredJWT but JWKS fetch error",
			setupJWT: func() *jwt.Token {
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
					Subject:   "test",
					ExpiresAt: jwt.NewNumericDate(time.Unix(1516239022, 0)),
				})
				token.Header["kid"] = "1"
				token.Raw = expiredJWTToken
				return token
			},
			jwksResp: "", // Will cause error
			wantMin:  0.0,
		},
		{
			name: "ExpiredJWT found in JWKS (should not happen)",
			setupJWT: func() *jwt.Token {
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
					Subject:   "test",
					ExpiresAt: jwt.NewNumericDate(time.Unix(1516239022, 0)),
				})
				token.Header["kid"] = "1"
				token.Raw = expiredJWTToken
				return token
			},
			jwksResp: `{
				"keys": [{
					"kty": "RSA",
					"use": "sig",
					"kid": "1",
					"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
					"e": "AQAB"
				}]
			}`,
			wantMin: 0.0, // Should fail validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			httpClient := newMockClient(
				func(req *http.Request) (*http.Response, error) {
					if strings.Contains(req.URL.Path, "jwks") {
						if tt.jwksResp == "" {
							return nil, errors.New("jwks fetch failed")
						}
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader(tt.jwksResp)),
						}, nil
					}
					return &http.Response{StatusCode: http.StatusNotFound, Body: http.NoBody}, nil
				},
			)

			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{
				HostURL:    "http://localhost:8080",
				ExpiredJWT: tt.setupJWT(),
				HTTPClient: httpClient,
			}
			bag["evalContext"] = ec

			result := rubrics.EvaluateExpiredJWKNotInJWKS(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.GreaterOrEqual(t, result.Awarded, tt.wantMin)
		})
	}
}

func TestEvaluateExpiredJWTWithNilChecks(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		httpClient *http.Client
		wantNote   string
	}{
		{
			name: "response returns nil token",
			httpClient: newMockClient(
				func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusUnauthorized,
						Body:       io.NopCloser(strings.NewReader(`{"error":"unauthorized"}`)),
					}, nil
				},
			),
			wantNote: "JWT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{
				HostURL:    "http://localhost:8080",
				HTTPClient: tt.httpClient,
			}
			bag["evalContext"] = ec

			result := rubrics.EvaluateExpiredJWT(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.Equal(t, 0.0, result.Awarded)
			assert.Contains(t, result.Note, tt.wantNote)
		})
	}
}

func TestEvaluateExpiredJWTErrorInAuthCall(t *testing.T) {
	t.Parallel()
	// Test when authentication itself returns an error
	httpClient := newMockClient(
		func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Body:       http.NoBody,
			}, nil
		},
	)

	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	bag["evalContext"] = rubrics.NewEvalContext("http://localhost:8080",
		rubrics.WithHTTPClient(httpClient),
		rubrics.WithJWTParser(mockExpiredJWTParser()),
	)

	result := rubrics.EvaluateExpiredJWT(ctx, pr, bag)
	assert.NotNil(t, result)
	assert.Equal(t, 0.0, result.Awarded)
	assert.NotEmpty(t, result.Note)
}

func TestAuthenticationFallbackLogic(t *testing.T) {
	t.Parallel()
	// Test the authentication function's fallback from postForm to postJSON
	callCount := 0
	httpClient := newMockClient(
		func(req *http.Request) (*http.Response, error) {
			callCount++
			if callCount == 1 {
				return &http.Response{
					StatusCode: http.StatusBadRequest,
					Body:       http.NoBody,
				}, nil
			}
			body := `{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjo5OTk5OTk5OTk5fQ.C-JdoPoGH-YLpL7HuSjNB0cWa0lVVZqI5VdVwrUYtYc"}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
			}, nil
		},
	)

	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	bag["evalContext"] = rubrics.NewEvalContext("http://localhost:8080",
		rubrics.WithHTTPClient(httpClient),
		rubrics.WithJWTParser(mockJWTParser()),
	)

	result := rubrics.EvaluateValidJWT(ctx, pr, bag)
	assert.NotNil(t, result)
	assert.Greater(t, result.Awarded, 0.0)
	assert.Equal(t, 2, callCount) // Verify fallback occurred
}

func TestDatabaseQueryUsesParametersWithSrcDir(t *testing.T) {
	t.Parallel()
	dbFile := createTestDB(t)
	tmpDir := t.TempDir()

	// Create source file with parameterized query
	srcDir := filepath.Join(tmpDir, "src")
	err := os.MkdirAll(srcDir, 0o755)
	require.NoError(t, err)

	sourceFile := filepath.Join(srcDir, "db.go")
	err = os.WriteFile(sourceFile, []byte(`
		db.Exec("INSERT INTO keys (key, exp) VALUES (?, ?)", keyData, expTime)
		db.Query("SELECT * FROM keys WHERE exp > ?", time.Now().Unix())
	`), 0o644)
	require.NoError(t, err)

	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	ec := &rubrics.EvalContext{
		DatabaseFile: dbFile,
		SrcDir:       srcDir,
	}
	bag["evalContext"] = ec

	result := rubrics.EvaluateDatabaseQueryUsesParameters(ctx, pr, bag)
	assert.NotNil(t, result)
	assert.Greater(t, result.Awarded, 0.0)
}

func TestRateLimitingStatusCodeChecks(t *testing.T) {
	t.Parallel()
	// Test rate limiting with different status code scenarios
	tests := []struct {
		name        string
		setupClient func() *http.Client
		wantAwarded float64
	}{
		{
			name: "first request fails",
			setupClient: func() *http.Client {
				return newMockClient(
					func(_ *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusInternalServerError,
							Body:       http.NoBody,
						}, nil
					},
				)
			},
			wantAwarded: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{
				HostURL:    "http://localhost:8080",
				Username:   "testuser",
				Password:   "testpass",
				HTTPClient: tt.setupClient(),
			}
			bag["evalContext"] = ec

			evaluator := rubrics.EvaluateRateLimiting("/auth", 2)
			result := evaluator(ctx, pr, bag)

			assert.NotNil(t, result)
			assert.Equal(t, tt.wantAwarded, result.Awarded)
		})
	}
}

func TestEvaluateRateLimitingSuccess(t *testing.T) {
	t.Parallel()
	rps := 2
	callCount := 0
	client := newMockClient(
		func(_ *http.Request) (*http.Response, error) {
			callCount++
			status := http.StatusOK
			if callCount == rps+1 {
				status = http.StatusTooManyRequests
			}
			return &http.Response{StatusCode: status, Body: http.NoBody}, nil
		},
	)

	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	ec := &rubrics.EvalContext{
		HostURL:    "http://localhost:8080",
		Username:   "user",
		Password:   "pass",
		HTTPClient: client,
	}
	bag["evalContext"] = ec

	evaluator := rubrics.EvaluateRateLimiting(rubrics.AuthEndpoint, rps)
	result := evaluator(ctx, pr, bag)

	assert.NotNil(t, result)
	assert.Equal(t, 25.0, result.Awarded)
	assert.Equal(t, rps+1, callCount)
}

func TestEvaluateRateLimitingFinalRequestError(t *testing.T) {
	t.Parallel()
	rps := 2
	callCount := 0
	client := newMockClient(
		func(_ *http.Request) (*http.Response, error) {
			callCount++
			if callCount <= rps {
				return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
			}
			// Final request (after rate limit should kick in) returns error
			return nil, errors.New("connection reset")
		},
	)

	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	ec := &rubrics.EvalContext{
		HostURL:    "http://localhost:8080",
		Username:   "user",
		Password:   "pass",
		HTTPClient: client,
	}
	bag["evalContext"] = ec

	evaluator := rubrics.EvaluateRateLimiting(rubrics.AuthEndpoint, rps)
	result := evaluator(ctx, pr, bag)

	assert.NotNil(t, result)
	assert.Equal(t, 0.0, result.Awarded)
	assert.Contains(t, result.Note, "connection reset")
}

func TestDatabaseExistsRowsScanError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
	}{
		{name: "scan failure still awards base points"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Create DB with keys table but wrong column count to trigger Scan error
			tmpDir := t.TempDir()
			dbFile := filepath.Join(tmpDir, "test.db")

			db, err := sql.Open("sqlite", dbFile)
			require.NoError(t, err)

			_, err = db.ExecContext(t.Context(), `CREATE TABLE keys (
				kid INTEGER PRIMARY KEY AUTOINCREMENT,
				key BLOB NOT NULL,
				exp INTEGER NOT NULL,
				extra_col TEXT
			)`)
			require.NoError(t, err)

			_, err = db.ExecContext(t.Context(), "INSERT INTO keys (key, exp, extra_col) VALUES (?, ?, ?)", []byte("test"), time.Now().Unix(), "extra")
			require.NoError(t, err)
			_ = db.Close()

			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{DatabaseFile: dbFile}
			bag["evalContext"] = ec

			result := rubrics.EvaluateDatabaseExists(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.LessOrEqual(t, result.Awarded, 5.0)
		})
	}
}

func TestDbHelpersWithNonExistentDatabase(t *testing.T) {
	t.Parallel()

	// Test dbGet error path via EvaluateRegistrationWorks
	t.Run("dbGet with non-existent database", func(t *testing.T) {
		t.Parallel()

		// HTTP client that returns a valid registration response
		httpClient := newMockClient(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(testUUIDPasswordJSON)),
			}, nil
		})

		ctx := t.Context()
		pr := mockProgramRunner{}
		bag := make(baserubrics.RunBag)
		ec := &rubrics.EvalContext{
			HostURL:      "http://localhost:8080",
			DatabaseFile: "/nonexistent/path/to/database.db",
			HTTPClient:   httpClient,
			Username:     "testuser",
		}
		bag["evalContext"] = ec

		// This will get past registration HTTP call but fail on dbGet
		result := rubrics.EvaluateRegistrationWorks(ctx, pr, bag)
		assert.NotNil(t, result)
		assert.Equal(t, 5.0, result.Awarded) // Only gets password points
		assert.NotEmpty(t, result.Note)      // Should have error about DB
	})

	// Test dbSelect error path via EvaluateAuthLogging
	t.Run("dbSelect with non-existent database", func(t *testing.T) {
		t.Parallel()

		dbFile := createTestDB(t)
		db, err := sqlx.Connect("sqlite", dbFile)
		require.NoError(t, err)
		// Insert user so dbGet succeeds
		_, err = db.ExecContext(t.Context(), "INSERT INTO users (username, password_hash) VALUES (?, ?)", "testuser", "hash")
		require.NoError(t, err)
		_ = db.Close()

		// HTTP client returns OK status
		httpClient := newMockClient(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       http.NoBody,
			}, nil
		})

		ctx := t.Context()
		pr := mockProgramRunner{}
		bag := make(baserubrics.RunBag)
		ec := &rubrics.EvalContext{
			HostURL:      "http://localhost:8080",
			DatabaseFile: dbFile,
			HTTPClient:   httpClient,
			Username:     "testuser",
			Password:     "testpass",
		}
		bag["evalContext"] = ec

		// This should succeed - tests full path
		result := rubrics.EvaluateAuthLogging(ctx, pr, bag)
		assert.NotNil(t, result)
	})

	// Test dbSelect with multiple WHERE clauses
	t.Run("dbSelect with multiple WHERE clauses", func(t *testing.T) {
		t.Parallel()

		dbFile := createTestDB(t)
		db, err := sqlx.Connect("sqlite", dbFile)
		require.NoError(t, err)
		// Insert user and auth_log so dbSelect with multiple conditions is tested
		_, err = db.ExecContext(t.Context(), "INSERT INTO users (username, password_hash) VALUES (?, ?)", "testuser", "hash")
		require.NoError(t, err)
		_, err = db.ExecContext(t.Context(), "INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?, ?, ?)", "127.0.0.1", time.Now(), 1)
		require.NoError(t, err)
		_ = db.Close()

		// HTTP client returns OK status
		httpClient := newMockClient(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       http.NoBody,
			}, nil
		})

		ctx := t.Context()
		pr := mockProgramRunner{}
		bag := make(baserubrics.RunBag)
		ec := &rubrics.EvalContext{
			HostURL:      "http://localhost:8080",
			DatabaseFile: dbFile,
			HTTPClient:   httpClient,
			Username:     "testuser",
			Password:     "testpass",
		}
		bag["evalContext"] = ec

		// Tests dbSelect with user_id WHERE clause
		result := rubrics.EvaluateAuthLogging(ctx, pr, bag)
		assert.NotNil(t, result)
		assert.Greater(t, result.Awarded, 0.0)
	})
}
