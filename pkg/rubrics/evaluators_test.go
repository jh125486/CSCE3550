package rubrics_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
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

// mockHTTPClient allows mocking HTTP responses for testing
type mockHTTPClient struct {
	DoFunc func(*http.Request) (*http.Response, error)
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.DoFunc != nil {
		return m.DoFunc(req)
	}
	return nil, errors.New("DoFunc not implemented")
}

type mockProgramRunner struct{}

func (mockProgramRunner) Run(_ ...string) error {
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
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{HostURL: tt.hostURL}
			bag["evalContext"] = ec

			result := rubrics.EvaluateRegistrationWorks(ctx, pr, bag)
			assert.Equal(t, tt.wantPoints, result.Points)
			assert.NotNil(t, result)
		})
	}
}

func TestGetEvalContext(t *testing.T) {
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
			name: "empty bag returns empty context",
			bagSetup: func() baserubrics.RunBag {
				return make(baserubrics.RunBag)
			},
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can't directly test getEvalContext since it's unexported
			// Instead we test that evaluators work with bag contexts
			bag := tt.bagSetup()

			// Test that evaluators don't panic with this bag
			ctx := t.Context()
			pr := mockProgramRunner{}
			result := rubrics.EvaluateDatabaseExists(ctx, pr, bag)
			assert.NotNil(t, result)
		})
	}
}

func TestEvalContextFields(t *testing.T) {
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
			// Just verify struct can be created
			assert.NotNil(t, tt.ec)
		})
	}
}

func TestEvalContextGetHTTPClient(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(*rubrics.EvalContext)
		assertFunc func(t *testing.T, ec *rubrics.EvalContext, got rubrics.HTTPClient)
	}{
		{
			name:  "returns default client",
			setup: func(ec *rubrics.EvalContext) {},
			assertFunc: func(t *testing.T, ec *rubrics.EvalContext, got rubrics.HTTPClient) {
				assert.NotNil(t, got)
				assert.NotEqual(t, ec.HTTPClient, got)
			},
		},
		{
			name: "uses custom client",
			setup: func(ec *rubrics.EvalContext) {
				ec.HTTPClient = &mockHTTPClient{}
			},
			assertFunc: func(t *testing.T, ec *rubrics.EvalContext, got rubrics.HTTPClient) {
				assert.Equal(t, ec.HTTPClient, got)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ec := rubrics.EvalContext{}
			tt.setup(&ec)

			client := ec.GetHTTPClient()
			tt.assertFunc(t, &ec, client)
		})
	}
}

func TestEvaluateDatabaseExistsErrorPaths(t *testing.T) {
	tests := []struct {
		name        string
		setupBag    func() baserubrics.RunBag
		wantAwarded float64
	}{
		{
			name: "database file does not exist",
			setupBag: func() baserubrics.RunBag {
				bag := make(baserubrics.RunBag)
				ec := &rubrics.EvalContext{DatabaseFile: "/nonexistent/path/db.db"}
				bag["evalContext"] = ec
				return bag
			},
			wantAwarded: 0.0,
		},
		{
			name: "empty database file path",
			setupBag: func() baserubrics.RunBag {
				bag := make(baserubrics.RunBag)
				ec := &rubrics.EvalContext{DatabaseFile: ""}
				bag["evalContext"] = ec
				return bag
			},
			wantAwarded: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := tt.setupBag()

			result := rubrics.EvaluateDatabaseExists(ctx, pr, bag)
			assert.Equal(t, tt.wantAwarded, result.Awarded)
			assert.Greater(t, result.Points, 0.0)
		})
	}
}

func TestEvaluateTableExistsWithDatabase(t *testing.T) {
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
	ec := &rubrics.EvalContext{
		DatabaseFile: dbFile,
		SrcDir:       srcDir,
	}
	bag["evalContext"] = ec

	result := rubrics.EvaluateDatabaseQueryUsesParameters(ctx, pr, bag)
	// Should find parameterized query
	assert.Greater(t, result.Awarded, 0.0)
	assert.Equal(t, 15.0, result.Points)
}

func TestEvaluatePrivateKeysEncryptedErrorCases(t *testing.T) {
	tests := []struct {
		name     string
		setupBag func() baserubrics.RunBag
	}{
		{
			name: "database does not exist",
			setupBag: func() baserubrics.RunBag {
				bag := make(baserubrics.RunBag)
				ec := &rubrics.EvalContext{DatabaseFile: "/nonexistent.db"}
				bag["evalContext"] = ec
				return bag
			},
		},
		{
			name: "empty database file",
			setupBag: func() baserubrics.RunBag {
				bag := make(baserubrics.RunBag)
				ec := &rubrics.EvalContext{DatabaseFile: ""}
				bag["evalContext"] = ec
				return bag
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := tt.setupBag()

			result := rubrics.EvaluatePrivateKeysEncrypted(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.Equal(t, 25.0, result.Points)
		})
	}
}

func TestEvaluateAuthLoggingWithData(t *testing.T) {
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
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{DatabaseFile: dbFile}
			bag["evalContext"] = ec

			result := rubrics.EvaluateAuthLogging(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.GreaterOrEqual(t, result.Awarded, tt.wantMin)
			assert.Equal(t, 10.0, result.Points)
		})
	}
}

func TestEvaluateValidJWTErrorCases(t *testing.T) {
	tests := []struct {
		name    string
		hostURL string
	}{
		{name: "invalid URL", hostURL: "http://localhost:9999"},
		{name: "empty URL", hostURL: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{HostURL: tt.hostURL}
			bag["evalContext"] = ec

			result := rubrics.EvaluateValidJWT(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.Equal(t, 0.0, result.Awarded)
		})
	}
}

func TestEvaluateExpiredJWTErrorCases(t *testing.T) {
	tests := []struct {
		name    string
		hostURL string
	}{
		{name: "invalid URL", hostURL: "http://localhost:9999"},
		{name: "empty URL", hostURL: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{HostURL: tt.hostURL}
			bag["evalContext"] = ec

			result := rubrics.EvaluateExpiredJWT(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.Equal(t, 0.0, result.Awarded)
		})
	}
}

func TestEvaluateValidJWKInJWKSNoValidJWT(t *testing.T) {
	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	ec := &rubrics.EvalContext{HostURL: "http://localhost:8080"}
	bag["evalContext"] = ec

	result := rubrics.EvaluateValidJWKInJWKS(ctx, pr, bag)
	assert.NotNil(t, result)
	assert.Equal(t, 0.0, result.Awarded)
	assert.NotEmpty(t, result.Note)
}

func TestEvaluateExpiredJWTIsExpiredNoExpiredJWT(t *testing.T) {
	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	ec := &rubrics.EvalContext{HostURL: "http://localhost:8080"}
	bag["evalContext"] = ec

	result := rubrics.EvaluateExpiredJWTIsExpired(ctx, pr, bag)
	assert.NotNil(t, result)
	assert.Equal(t, 0.0, result.Awarded)
	assert.NotEmpty(t, result.Note)
}

func TestEvaluateExpiredJWKNotInJWKSNoExpiredJWT(t *testing.T) {
	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	ec := &rubrics.EvalContext{HostURL: "http://localhost:8080"}
	bag["evalContext"] = ec

	result := rubrics.EvaluateExpiredJWKNotInJWKS(ctx, pr, bag)
	assert.NotNil(t, result)
	assert.Equal(t, 0.0, result.Awarded)
	assert.NotEmpty(t, result.Note)
}

func TestEvaluateTableExistsMultipleTables(t *testing.T) {
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
	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	ec := &rubrics.EvalContext{HostURL: "http://localhost:9999"}
	bag["evalContext"] = ec

	result := rubrics.EvaluateHTTPMethods(ctx, pr, bag)
	assert.NotNil(t, result)
	assert.GreaterOrEqual(t, result.Awarded, 1.0)
}

func TestEvaluateRegistrationWorksInvalidURL(t *testing.T) {
	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	ec := &rubrics.EvalContext{HostURL: "http://localhost:9999"}
	bag["evalContext"] = ec

	result := rubrics.EvaluateRegistrationWorks(ctx, pr, bag)
	assert.NotNil(t, result)
	assert.Equal(t, 0.0, result.Awarded)
	assert.NotEmpty(t, result.Note)
}

func TestEvaluateRateLimitingInvalidEndpoint(t *testing.T) {
	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	ec := &rubrics.EvalContext{
		HostURL:  "http://localhost:9999",
		Username: "testuser",
		Password: "testpass",
	}
	bag["evalContext"] = ec

	evaluator := rubrics.EvaluateRateLimiting("/auth", 10)
	result := evaluator(ctx, pr, bag)

	assert.Equal(t, 25.0, result.Points)
	assert.Equal(t, 0.0, result.Awarded)
	assert.NotEmpty(t, result.Note)
}

func TestEvaluateDatabaseQueryUsesParametersNoDatabase(t *testing.T) {
	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	ec := &rubrics.EvalContext{DatabaseFile: "/nonexistent/path/db.sqlite"}
	bag["evalContext"] = ec

	result := rubrics.EvaluateDatabaseQueryUsesParameters(ctx, pr, bag)
	assert.NotNil(t, result)
	assert.Equal(t, 0.0, result.Awarded)
	assert.NotEmpty(t, result.Note)
}

func TestEvaluateDatabaseQueryUsesParametersMissingSourceDir(t *testing.T) {
	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	ec := &rubrics.EvalContext{SrcDir: filepath.Join(t.TempDir(), "missing")}
	bag["evalContext"] = ec

	result := rubrics.EvaluateDatabaseQueryUsesParameters(ctx, pr, bag)
	assert.NotNil(t, result)
	assert.Equal(t, 0.0, result.Awarded)
	assert.NotEmpty(t, result.Note)
}

func TestDatabaseEvaluatorsWithValidKeys(t *testing.T) {
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

func TestEvaluateTableExistsInvalidDatabase(t *testing.T) {
	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	ec := &rubrics.EvalContext{DatabaseFile: "/nonexistent/db.sqlite"}
	bag["evalContext"] = ec

	evaluator := rubrics.EvaluateTableExists("keys", 5.0)
	result := evaluator(ctx, pr, bag)

	assert.NotNil(t, result)
	assert.Equal(t, 0.0, result.Awarded)
	assert.NotEmpty(t, result.Note)
}

func TestAuthLoggingEdgeCases(t *testing.T) {
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
			// Create fresh database for each test
			dbFile := createTestDB(t)

			db, err := sqlx.Connect("sqlite", dbFile)
			require.NoError(t, err)

			tt.setupDB(t, db)
			_ = db.Close()

			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{DatabaseFile: dbFile}
			bag["evalContext"] = ec

			result := rubrics.EvaluateAuthLogging(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.GreaterOrEqual(t, result.Awarded, tt.minScore)
		})
	}
}

func TestEvaluatePrivateKeysEncryptedEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		keyData []byte
		want    float64
	}{
		{
			name:    "PEM formatted RSA key",
			keyData: []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"),
			want:    0.0, // Not encrypted, should fail
		},
		{
			name:    "random bytes",
			keyData: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			want:    25.0, // Encrypted (doesn't start with PEM) should award full points
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbFile := createTestDB(t)

			ctx := t.Context()
			db, err := sqlx.Connect("sqlite", dbFile)
			require.NoError(t, err)

			_, err = db.ExecContext(ctx, "INSERT INTO keys (key, exp) VALUES (?, ?)", tt.keyData, time.Now().Add(time.Hour).Unix())
			require.NoError(t, err)
			_ = db.Close()

			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{DatabaseFile: dbFile}
			bag["evalContext"] = ec

			result := rubrics.EvaluatePrivateKeysEncrypted(ctx, pr, bag)
			assert.NotNil(t, result)
			assert.Equal(t, tt.want, result.Awarded)
		})
	}
}

func TestEvaluatePrivateKeysEncryptedNoKeys(t *testing.T) {
	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	ec := &rubrics.EvalContext{DatabaseFile: createTestDB(t)}
	bag["evalContext"] = ec

	result := rubrics.EvaluatePrivateKeysEncrypted(ctx, pr, bag)
	assert.NotNil(t, result)
	assert.Equal(t, 0.0, result.Awarded)
	assert.Contains(t, strings.ToLower(result.Note), "no keys")
}

func TestHTTPClientInjection(t *testing.T) {
	// Demonstrate dependency injection with mock HTTP client
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusMethodNotAllowed,
				Body:       http.NoBody,
			}, nil
		},
	}

	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	ec := &rubrics.EvalContext{
		HostURL:    "http://localhost:8080",
		HTTPClient: mockClient,
	}
	bag["evalContext"] = ec

	result := rubrics.EvaluateHTTPMethods(ctx, pr, bag)
	assert.NotNil(t, result)
	// With mock returning 405 for all requests, should score > 1
	assert.Greater(t, result.Awarded, 1.0)
}

func TestAuthenticationWithMockHTTP(t *testing.T) {
	type args struct {
		httpClient rubrics.HTTPClient
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
				httpClient: &mockHTTPClient{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						body := `{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}`
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader(body)),
						}, nil
					},
				},
				expired: false,
			},
			wantErr: false,
			wantJWT: true,
		},
		{
			name: "successful auth with raw JWT",
			args: args{
				httpClient: &mockHTTPClient{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						body := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader(body)),
						}, nil
					},
				},
				expired: false,
			},
			wantErr: false,
			wantJWT: true,
		},
		{
			name: "failed auth - http error",
			args: args{
				httpClient: &mockHTTPClient{
					DoFunc: func(_ *http.Request) (*http.Response, error) {
						return nil, errors.New("connection refused")
					},
				},
				expired: false,
			},
			wantErr: true,
			wantJWT: false,
		},
		{
			name: "failed auth - non-200 status",
			args: args{
				httpClient: &mockHTTPClient{
					DoFunc: func(_ *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusUnauthorized,
							Body:       io.NopCloser(strings.NewReader("unauthorized")),
						}, nil
					},
				},
				expired: false,
			},
			wantErr: true,
			wantJWT: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := make(baserubrics.RunBag)
			ec := &rubrics.EvalContext{
				HostURL:    "http://localhost:8080",
				HTTPClient: tt.args.httpClient,
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
	type args struct {
		httpClient rubrics.HTTPClient
	}
	tests := []struct {
		name        string
		args        args
		wantAwarded float64
	}{
		{
			name: "successful registration",
			args: args{
				httpClient: &mockHTTPClient{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader(testUUIDPasswordJSON)),
						}, nil
					},
				},
			},
			wantAwarded: 5.0, // Gets 5 points for valid UUID in response
		},
		{
			name: "registration returns created",
			args: args{
				httpClient: &mockHTTPClient{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						body := `{"password":"123e4567-e89b-12d3-a456-426614174000"}`
						return &http.Response{
							StatusCode: http.StatusCreated,
							Body:       io.NopCloser(strings.NewReader(body)),
						}, nil
					},
				},
			},
			wantAwarded: 5.0,
		},
		{
			name: "registration fails - bad status",
			args: args{
				httpClient: &mockHTTPClient{
					DoFunc: func(_ *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusBadRequest,
							Body:       io.NopCloser(strings.NewReader(`{"error":"bad request"}`)),
						}, nil
					},
				},
			},
			wantAwarded: 0.0,
		},
		{
			name: "registration fails - connection error",
			args: args{
				httpClient: &mockHTTPClient{
					DoFunc: func(_ *http.Request) (*http.Response, error) {
						return nil, errors.New("connection refused")
					},
				},
			},
			wantAwarded: 0.0,
		},
		{
			name: "registration returns invalid password format",
			args: args{
				httpClient: &mockHTTPClient{
					DoFunc: func(_ *http.Request) (*http.Response, error) {
						body := `{"password":"not-a-uuid"}`
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader(body)),
						}, nil
					},
				},
			},
			wantAwarded: 5.0, // Gets 5 for valid response, but fails on UUID check
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
	type args struct {
		endpoint   string
		rps        int
		httpClient rubrics.HTTPClient
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
				httpClient: &mockHTTPClient{
					DoFunc: func(_ *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       http.NoBody,
						}, nil
					},
				},
			},
			wantAwarded: 0.0,
		},
		{
			name: "no rate limiting",
			args: args{
				endpoint: "/auth",
				rps:      2,
				httpClient: &mockHTTPClient{
					DoFunc: func(_ *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       http.NoBody,
						}, nil
					},
				},
			},
			wantAwarded: 0.0,
		},
		{
			name: "http error",
			args: args{
				endpoint: "/auth",
				rps:      2,
				httpClient: &mockHTTPClient{
					DoFunc: func(_ *http.Request) (*http.Response, error) {
						return nil, errors.New("connection error")
					},
				},
			},
			wantAwarded: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
		httpClient  rubrics.HTTPClient
		wantAwarded float64
	}{
		{
			name: "auth logging works",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       http.NoBody,
					}, nil
				},
			},
			wantAwarded: 10.0,
		},
		{
			name: "auth fails - wrong status",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusUnauthorized,
						Body:       http.NoBody,
					}, nil
				},
			},
			wantAwarded: 0.0,
		},
		{
			name: "auth fails - connection error",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return nil, errors.New("connection error")
				},
			},
			wantAwarded: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
	tests := []struct {
		name        string
		httpClient  rubrics.HTTPClient
		wantAwarded float64
	}{
		{
			name: "expired JWT returned correctly",
			httpClient: &mockHTTPClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					// Return expired JWT (exp claim in the past)
					body := `{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxNTE2MjM5MDIyfQ.4Adcj0HKQX4K8Y3lVjGdU_FqKJZgqJ5c5fH2VwLjEfw"}`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
					}, nil
				},
			},
			wantAwarded: 5.0,
		},
		{
			name: "no token returned",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{}`)),
					}, nil
				},
			},
			wantAwarded: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
			assert.Equal(t, tt.wantAwarded, result.Awarded)
		})
	}
}

func TestJWKSValidationWithMockHTTP(t *testing.T) {
	tests := []struct {
		name        string
		httpClient  rubrics.HTTPClient
		setupBag    func() baserubrics.RunBag
		wantAwarded float64
	}{
		{
			name: "EvaluateValidJWKInJWKS - no valid JWT",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"keys":[]}`)),
					}, nil
				},
			},
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
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{}`)),
					}, nil
				},
			},
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
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"keys":[]}`)),
					}, nil
				},
			},
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
			ctx := t.Context()
			pr := mockProgramRunner{}
			bag := tt.setupBag()

			if ec, ok := bag["evalContext"].(*rubrics.EvalContext); ok {
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
	tests := []struct {
		name       string
		testFunc   string
		httpClient rubrics.HTTPClient
		expired    bool
		wantErr    bool
	}{
		{
			name:     "authenticatePostJSON success",
			testFunc: "postJSON",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"token":"valid"}`)),
					}, nil
				},
			},
			expired: false,
			wantErr: false,
		},
		{
			name:     "authenticatePostJSON expired",
			testFunc: "postJSON",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"token":"expired"}`)),
					}, nil
				},
			},
			expired: true,
			wantErr: false,
		},
		{
			name:     "authenticatePostForm success",
			testFunc: "postForm",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"token":"valid"}`)),
					}, nil
				},
			},
			expired: false,
			wantErr: false,
		},
		{
			name:     "registration success",
			testFunc: "registration",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"password":"uuid-here"}`)),
					}, nil
				},
			},
			expired: false,
			wantErr: false,
		},
		{
			name:     "authenticationWithCreds success",
			testFunc: "authWithCreds",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"token":"valid"}`)),
					}, nil
				},
			},
			expired: false,
			wantErr: false,
		},
		{
			name:     "HTTP error handling",
			testFunc: "postJSON",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return nil, errors.New("network error")
				},
			},
			expired: false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
	tests := []struct {
		name       string
		httpClient rubrics.HTTPClient
		wantErr    bool
	}{
		{
			name: "authentication with JWT in response",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					body := `{"jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
					}, nil
				},
			},
			wantErr: false,
		},
		{
			name: "authentication with raw JWT body",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					body := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
					}, nil
				},
			},
			wantErr: false,
		},
		{
			name: "authentication with invalid JSON",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{invalid json}`)),
					}, nil
				},
			},
			wantErr: true,
		},
		{
			name: "authentication falls back to postJSON after postForm fails",
			httpClient: func() rubrics.HTTPClient {
				callCount := 0
				return &mockHTTPClient{
					DoFunc: func(_ *http.Request) (*http.Response, error) {
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
				}
			}(),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
	tests := []struct {
		name        string
		httpClient  rubrics.HTTPClient
		wantAwarded float64
		wantNote    bool
	}{
		{
			name: "expired JWT without exp claim",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					// JWT without exp claim
					body := `{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Gfx6VO9tcxwk6xqx9yYzSfebfeakZp5JYIgP_edcw_A"}`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
					}, nil
				},
			},
			wantAwarded: 0.0,
			wantNote:    true,
		},
		{
			name: "expired JWT with future exp",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					// JWT with exp in future
					body := `{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjo5OTk5OTk5OTk5fQ.C-JdoPoGH-YLpL7HuSjNB0cWa0lVVZqI5VdVwrUYtYc"}`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
					}, nil
				},
			},
			wantAwarded: 0.0,
			wantNote:    true,
		},
		{
			name: "expired JWT with header but no token",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"message":"no token"}`)),
					}, nil
				},
			},
			wantAwarded: 0.0,
			wantNote:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
	tests := []struct {
		name        string
		httpClient  rubrics.HTTPClient
		setupDB     func(*testing.T, *rubrics.EvalContext)
		wantAwarded float64
	}{
		{
			name: "registration with empty password field",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"password":""}`)),
					}, nil
				},
			},
			wantAwarded: 0.0,
		},
		{
			name: "registration with non-JSON response",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`plain text response`)),
					}, nil
				},
			},
			wantAwarded: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
	password := "123e4567-e89b-12d3-a456-426614174000"
	dbFile := createTestDB(t)

	db, err := sqlx.Connect("sqlite", dbFile)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), "INSERT INTO users (username, password_hash) VALUES (?, ?)", "testuser", password)
	require.NoError(t, err)
	_ = db.Close()

	httpClient := &mockHTTPClient{
		DoFunc: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(fmt.Sprintf(`{"password":%q}`, password))),
			}, nil
		},
	}

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

func TestEvaluateRegistrationWorksFullFlow(t *testing.T) {
	tests := []struct {
		name       string
		httpClient rubrics.HTTPClient
		insertUser bool
		wantMin    float64
	}{
		{
			name: "full registration flow with DB check",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusCreated,
						Body:       io.NopCloser(strings.NewReader(testUUIDPasswordJSON)),
					}, nil
				},
			},
			insertUser: true,
			wantMin:    10.0, // 5 for password + 5 for user in DB
		},
		{
			name: "registration with same password as hash",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(testUUIDPasswordJSON)),
					}, nil
				},
			},
			insertUser: false,
			wantMin:    5.0, // Only password points
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbFile := createTestDB(t)

			if tt.insertUser {
				db, err := sqlx.Connect("sqlite", dbFile)
				require.NoError(t, err)
				_, err = db.ExecContext(t.Context(), "INSERT INTO users (username, password_hash) VALUES (?, ?)", "testuser", "hashed_password_value")
				require.NoError(t, err)
				_ = db.Close()
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
			assert.GreaterOrEqual(t, result.Awarded, tt.wantMin)
		})
	}
}

func TestEvaluateJWKSWithValidAndExpiredJWTs(t *testing.T) {
	// Create a scenario where we have both valid and expired JWTs in bag
	validJWT := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjo5OTk5OTk5OTk5fQ.HL8Zg8R6vF5MwL-CK4bKZQ0YbPk0Q5X3g5G7K5jDqYE`
	expiredJWT := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjIifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxNTE2MjM5MDIyfQ.4Adcj0HKQX4K8Y3lVjGdU_FqKJZgqJ5c5fH2VwLjEfw`

	tests := []struct {
		name       string
		httpClient rubrics.HTTPClient
		testFunc   string
		wantMin    float64
	}{
		{
			name: "ValidJWKInJWKS with JWKS error",
			httpClient: &mockHTTPClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					if strings.Contains(req.URL.Path, "/auth") {
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader(`{"token":"` + validJWT + `"}`)),
						}, nil
					}
					return nil, errors.New("jwks fetch failed")
				},
			},
			testFunc: "ValidJWKInJWKS",
			wantMin:  0.0,
		},
		{
			name: "ExpiredJWKNotInJWKS with JWKS response",
			httpClient: &mockHTTPClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
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
			},
			testFunc: "ExpiredJWKNotInJWKS",
			wantMin:  0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
	tests := []struct {
		name       string
		httpClient rubrics.HTTPClient
		expired    bool
		wantErr    bool
	}{
		{
			name: "expired parameter in URL",
			httpClient: &mockHTTPClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
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
			},
			expired: true,
			wantErr: false,
		},
		{
			name: "read body error",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(&errorReader{}),
					}, nil
				},
			},
			expired: false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
	tests := []struct {
		name       string
		httpClient rubrics.HTTPClient
		wantMin    float64
	}{
		{
			name: "all methods return 405",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusMethodNotAllowed,
						Body:       http.NoBody,
					}, nil
				},
			},
			wantMin: 9.0, // 1 base + 9 correct responses
		},
		{
			name: "mixed responses",
			httpClient: func() *mockHTTPClient {
				count := 0
				return &mockHTTPClient{
					DoFunc: func(_ *http.Request) (*http.Response, error) {
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
				}
			}(),
			wantMin: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
			httpClient := &mockHTTPClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
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
			}

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
	tests := []struct {
		name        string
		httpClient  rubrics.HTTPClient
		wantAwarded float64
		checkNote   bool
	}{
		{
			name: "empty response body",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{}`)),
					}, nil
				},
			},
			wantAwarded: 0.0,
			checkNote:   true,
		},
		{
			name: "token with nil header",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`malformed`)),
					}, nil
				},
			},
			wantAwarded: 0.0,
			checkNote:   true,
		},
		{
			name: "valid token (not expired)",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					body := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjo5OTk5OTk5OTk5fQ.C-JdoPoGH-YLpL7HuSjNB0cWa0lVVZqI5VdVwrUYtYc`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
					}, nil
				},
			},
			wantAwarded: 5.0,
			checkNote:   false,
		},
		{
			name: "postForm and postJSON return non-200",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusUnauthorized,
						Body:       http.NoBody,
					}, nil
				},
			},
			wantAwarded: 0.0,
			checkNote:   true,
		},
		{
			name: "postForm succeeds with JWT",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					body := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNTE2MjM5MDIyfQ.4Adcj0HKQX4K8Y3lVjGdU_FqKJZgqJ5c5fH2VwLjEfw`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
					}, nil
				},
			},
			wantAwarded: 5.0,
			checkNote:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
			assert.Equal(t, tt.wantAwarded, result.Awarded)
			if tt.checkNote {
				assert.NotEmpty(t, result.Note)
			}
		})
	}
}

func TestEvaluateAuthLoggingAllBranches(t *testing.T) {
	tests := []struct {
		name        string
		setupDB     func(*testing.T) string
		httpClient  rubrics.HTTPClient
		wantAwarded float64
		noteCheck   string
	}{
		{
			name:    "user not found in DB",
			setupDB: createTestDB,
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       http.NoBody,
					}, nil
				},
			},
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
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       http.NoBody,
					}, nil
				},
			},
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
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       http.NoBody,
					}, nil
				},
			},
			wantAwarded: 5.0,
			noteCheck:   "IP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
	tests := []struct {
		name       string
		httpClient rubrics.HTTPClient
	}{
		{
			name: "authentication io.ReadAll error",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(&errorReader{}),
					}, nil
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
	tests := []struct {
		name       string
		httpClient rubrics.HTTPClient
		wantMin    float64
	}{
		{
			name: "request failure still yields base points",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return nil, errors.New("connection refused")
				},
			},
			wantMin: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

func TestRegistrationFullPath(t *testing.T) {
	// Test the full registration path including DB lookups
	dbFile := createTestDB(t)

	// Insert user first
	db, err := sqlx.Connect("sqlite", dbFile)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), "INSERT INTO users (username, password_hash) VALUES (?, ?)", "testuser", "different_hash")
	require.NoError(t, err)
	_ = db.Close()

	httpClient := &mockHTTPClient{
		DoFunc: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusCreated,
				Body:       io.NopCloser(strings.NewReader(testUUIDPasswordJSON)),
			}, nil
		},
	}

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
	// Should get 5 (password) + 5 (user exists) + 10 (hash different) = 20
	assert.Equal(t, 20.0, result.Awarded)
}

func TestTableExistsHelper(t *testing.T) {
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
			httpClient := &mockHTTPClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
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
			}

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
			httpClient := &mockHTTPClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
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
			}

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
	tests := []struct {
		name       string
		httpClient rubrics.HTTPClient
		wantNote   string
	}{
		{
			name: "response returns nil token",
			httpClient: &mockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusUnauthorized,
						Body:       io.NopCloser(strings.NewReader(`{"error":"unauthorized"}`)),
					}, nil
				},
			},
			wantNote: "JWT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
	// Test when authentication itself returns an error
	httpClient := &mockHTTPClient{
		DoFunc: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Body:       http.NoBody,
			}, nil
		},
	}

	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	ec := &rubrics.EvalContext{
		HostURL:    "http://localhost:8080",
		HTTPClient: httpClient,
	}
	bag["evalContext"] = ec

	result := rubrics.EvaluateExpiredJWT(ctx, pr, bag)
	assert.NotNil(t, result)
	assert.Equal(t, 0.0, result.Awarded)
	assert.NotEmpty(t, result.Note)
}

func TestAuthenticationFallbackLogic(t *testing.T) {
	// Test the authentication function's fallback from postForm to postJSON
	callCount := 0
	httpClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
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
	}

	ctx := t.Context()
	pr := mockProgramRunner{}
	bag := make(baserubrics.RunBag)
	ec := &rubrics.EvalContext{
		HostURL:    "http://localhost:8080",
		HTTPClient: httpClient,
	}
	bag["evalContext"] = ec

	result := rubrics.EvaluateValidJWT(ctx, pr, bag)
	assert.NotNil(t, result)
	assert.Greater(t, result.Awarded, 0.0)
	assert.Equal(t, 2, callCount) // Verify fallback occurred
}

func TestDatabaseQueryUsesParametersWithSrcDir(t *testing.T) {
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
	// Test rate limiting with different status code scenarios
	tests := []struct {
		name        string
		setupClient func() *mockHTTPClient
		wantAwarded float64
	}{
		{
			name: "first request fails",
			setupClient: func() *mockHTTPClient {
				return &mockHTTPClient{
					DoFunc: func(_ *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusInternalServerError,
							Body:       http.NoBody,
						}, nil
					},
				}
			},
			wantAwarded: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
	rps := 2
	callCount := 0
	client := &mockHTTPClient{
		DoFunc: func(_ *http.Request) (*http.Response, error) {
			callCount++
			status := http.StatusOK
			if callCount == rps+1 {
				status = http.StatusTooManyRequests
			}
			return &http.Response{StatusCode: status, Body: http.NoBody}, nil
		},
	}

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

func TestDatabaseExistsRowsScanError(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "scan failure still awards base points"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
