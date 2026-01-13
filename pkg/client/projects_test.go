package client_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/jh125486/CSCE3550/pkg/client"
	baseclient "github.com/jh125486/gradebot/pkg/client"
	baserubrics "github.com/jh125486/gradebot/pkg/rubrics"
	"github.com/stretchr/testify/assert"
)

type mockTransport struct {
	roundTrip func(*http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.roundTrip != nil {
		return m.roundTrip(req)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{}`)),
	}, nil
}

func newMockClient() *http.Client {
	return &http.Client{
		Transport: &mockTransport{},
	}
}

type stubProgram struct {
	runErr error
}

func (s *stubProgram) Path() string                                   { return "" }
func (s *stubProgram) Run(_ ...string) error                          { return s.runErr }
func (s *stubProgram) Do(string) (stdout, stderr []string, err error) { return nil, nil, nil }
func (s *stubProgram) Kill() error                                    { return nil }
func (s *stubProgram) Cleanup(context.Context) error                  { return nil }

func TestExecuteProject1_NilProgram(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	cfg := &baseclient.Config{
		Dir:    baseclient.WorkDir(t.TempDir()),
		RunCmd: "echo test",
		// ProgramBuilder is nil - exercises the default builder branch
	}

	// Will fail because echo isn't a long-running server, but covers the nil branch
	_ = client.ExecuteProject1(ctx, cfg, newMockClient(), 8080)
}

func TestExecuteProject1(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		port    int
		runCmd  string
		wantErr bool
	}{
		{
			name:    "valid port",
			port:    8080,
			runCmd:  "echo test",
			wantErr: false, // Won't error because program doesn't actually run
		},
		{
			name:    "program run fails",
			port:    8080,
			runCmd:  "nonexistent-cmd-123",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			runErr := error(nil)
			if tt.wantErr {
				runErr = errors.New("run failure")
			}

			ctx := t.Context()
			cfg := &baseclient.Config{
				Dir:    baseclient.WorkDir(t.TempDir()),
				RunCmd: tt.runCmd,
				ProgramBuilder: func(_, _ string) (baserubrics.ProgramRunner, error) {
					return &stubProgram{runErr: runErr}, nil
				},
			}

			err := client.ExecuteProject1(ctx, cfg, newMockClient(), tt.port)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestExecuteProject2_NilProgram(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	cfg := &baseclient.Config{
		Dir:    baseclient.WorkDir(t.TempDir()),
		RunCmd: "echo test",
	}
	_ = client.ExecuteProject2(ctx, cfg, newMockClient(), 8080, "test.db", ".")
}

func TestExecuteProject2(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		port         int
		databaseFile string
		codeDir      string
		runCmd       string
		wantErr      bool
	}{
		{
			name:         "valid parameters",
			port:         8080,
			databaseFile: "/tmp/test.db",
			codeDir:      ".",
			runCmd:       "echo test",
			wantErr:      false, // Won't error because program doesn't actually run
		},
		{
			name:         "program run fails",
			port:         8080,
			databaseFile: "/tmp/test.db",
			codeDir:      ".",
			runCmd:       "nonexistent-cmd-123",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			runErr := error(nil)
			if tt.wantErr {
				runErr = errors.New("run failure")
			}

			ctx := t.Context()
			cfg := &baseclient.Config{
				Dir:    baseclient.WorkDir(t.TempDir()),
				RunCmd: tt.runCmd,
				ProgramBuilder: func(_, _ string) (baserubrics.ProgramRunner, error) {
					return &stubProgram{runErr: runErr}, nil
				},
			}

			err := client.ExecuteProject2(ctx, cfg, newMockClient(), tt.port, tt.databaseFile, tt.codeDir)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestExecuteProject3_NilProgram(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	cfg := &baseclient.Config{
		Dir:    baseclient.WorkDir(t.TempDir()),
		RunCmd: "echo test",
	}
	_ = client.ExecuteProject3(ctx, cfg, newMockClient(), 8080, "test.db", ".")
}

func TestExecuteProject3(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		port         int
		databaseFile string
		codeDir      string
		runCmd       string
		wantErr      bool
	}{
		{
			name:         "valid parameters",
			port:         8080,
			databaseFile: "/tmp/test.db",
			codeDir:      ".",
			runCmd:       "echo test",
			wantErr:      false, // Won't error because program doesn't actually run
		},
		{
			name:         "program run fails",
			port:         8080,
			databaseFile: "/tmp/test.db",
			codeDir:      ".",
			runCmd:       "nonexistent-cmd-123",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			runErr := error(nil)
			if tt.wantErr {
				runErr = errors.New("run failure")
			}

			ctx := t.Context()
			cfg := &baseclient.Config{
				Dir:    baseclient.WorkDir(t.TempDir()),
				RunCmd: tt.runCmd,
				ProgramBuilder: func(_, _ string) (baserubrics.ProgramRunner, error) {
					return &stubProgram{runErr: runErr}, nil
				},
			}

			err := client.ExecuteProject3(ctx, cfg, newMockClient(), tt.port, tt.databaseFile, tt.codeDir)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
