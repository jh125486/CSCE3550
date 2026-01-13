package app_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/jh125486/CSCE3550/pkg/app"
	basecli "github.com/jh125486/gradebot/pkg/cli"
	baseclient "github.com/jh125486/gradebot/pkg/client"
	"github.com/stretchr/testify/require"
)

const defaultsName = "defaults"

type mockTransport struct {
	roundTrip func(*http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.roundTrip != nil {
		return m.roundTrip(req)
	}
	// Return a default success response
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("{}")),
	}, nil
}

func newMockClient() *http.Client {
	return &http.Client{
		Transport: &mockTransport{},
	}
}

func TestProject1CmdRun(t *testing.T) {
	t.Parallel()
	type args struct {
		port      int
		serverURL string
		client    *http.Client
		stdin     io.Reader
		stdout    io.Writer
	}
	tests := []struct {
		name    string
		args    args
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "successful run",
			args: args{
				port:   8080,
				client: newMockClient(),
				stdin:  strings.NewReader("n\n"),
				stdout: &bytes.Buffer{},
			},
			wantErr: require.NoError,
		},
		{
			name: "with server url",
			args: args{
				port:      8080,
				serverURL: "http://example.com",
				client:    newMockClient(),
				stdin:     strings.NewReader("n\n"),
				stdout:    &bytes.Buffer{},
			},
			wantErr: require.NoError,
		},
		// Covers ensureDeps nil checks
		{
			name: defaultsName,
			args: args{
				port: 8080,
			},
			wantErr: require.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Helper to clean up "defaults" test case
			port := tt.args.port
			if tt.name == defaultsName {
				// Start a dummy server to prevent hanging when using DefaultClient
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNotFound)
				}))
				defer ts.Close()

				addr := ts.Listener.Addr().String()
				// Extract port
				parts := strings.Split(addr, ":")
				var err error
				port, err = strconv.Atoi(parts[len(parts)-1])
				require.NoError(t, err)
			}

			cmd := app.Project1Cmd{
				CommonArgs: basecli.CommonArgs{
					Dir:       baseclient.WorkDir(t.TempDir()),
					RunCmd:    "echo test",
					Env:       map[string]string{},
					ServerURL: tt.args.serverURL,
				},
				Port:   port,
				Client: tt.args.client,
				Stdin:  tt.args.stdin,
				Stdout: tt.args.stdout,
			}

			err := cmd.Run(basecli.Context{Context: t.Context()})
			tt.wantErr(t, err)
		})
	}
}

func TestProject2CmdRun(t *testing.T) {
	t.Parallel()
	type args struct {
		port         int
		codeDir      string
		databaseFile string
		serverURL    string
		client       *http.Client
		stdin        io.Reader
		stdout       io.Writer
	}
	tests := []struct {
		name    string
		args    args
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "builds config correctly",
			args: args{
				port:         8080,
				codeDir:      ".",
				databaseFile: "test.db",
				client:       newMockClient(),
				stdin:        strings.NewReader("n\n"),
				stdout:       &bytes.Buffer{},
			},
			wantErr: require.NoError,
		},
		{
			name: "with server url",
			args: args{
				port:         8080,
				codeDir:      ".",
				databaseFile: "test.db",
				serverURL:    "http://example.com",
				client:       newMockClient(),
				stdin:        strings.NewReader("n\n"),
				stdout:       &bytes.Buffer{},
			},
			wantErr: require.NoError,
		},
		{
			name: defaultsName,
			args: args{
				port:    8080,
				codeDir: ".",
			},
			wantErr: require.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tempDir := t.TempDir()
			dbFile := tt.args.databaseFile
			if dbFile == "" {
				dbFile = "test.db"
			}

			// Helper to clean up "defaults" test case
			port := tt.args.port
			if tt.name == defaultsName {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNotFound)
				}))
				defer ts.Close()
				parts := strings.Split(ts.Listener.Addr().String(), ":")
				var err error
				port, err = strconv.Atoi(parts[len(parts)-1])
				require.NoError(t, err)
			}

			cmd := app.Project2Cmd{
				CommonArgs: basecli.CommonArgs{
					Dir:       baseclient.WorkDir(tempDir),
					RunCmd:    "echo test",
					Env:       map[string]string{},
					ServerURL: tt.args.serverURL,
				},
				Port:         port,
				DatabaseFile: tempDir + "/" + dbFile,
				CodeDir:      tt.args.codeDir,
				Client:       tt.args.client,
				Stdin:        tt.args.stdin,
				Stdout:       tt.args.stdout,
			}

			err := cmd.Run(basecli.Context{Context: t.Context()})
			tt.wantErr(t, err)
		})
	}
}

func TestProject3CmdRun(t *testing.T) {
	t.Parallel()
	type args struct {
		port         int
		codeDir      string
		databaseFile string
		serverURL    string
		client       *http.Client
		stdin        io.Reader
		stdout       io.Writer
	}
	tests := []struct {
		name    string
		args    args
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "successful run",
			args: args{
				port:         8080,
				codeDir:      ".",
				databaseFile: "test.db",
				client:       newMockClient(),
				stdin:        strings.NewReader("n\n"),
				stdout:       &bytes.Buffer{},
			},
			wantErr: require.NoError,
		},
		{
			name: "with server url",
			args: args{
				port:         8080,
				codeDir:      ".",
				databaseFile: "test.db",
				serverURL:    "http://example.com",
				client:       newMockClient(),
				stdin:        strings.NewReader("n\n"),
				stdout:       &bytes.Buffer{},
			},
			wantErr: require.NoError,
		},
		{
			name: defaultsName,
			args: args{
				port:    8080,
				codeDir: ".",
			},
			wantErr: require.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tempDir := t.TempDir()
			dbFile := tt.args.databaseFile
			if dbFile == "" {
				dbFile = "test.db"
			}

			// Helper to clean up "defaults" test case
			port := tt.args.port
			if tt.name == defaultsName {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNotFound)
				}))
				defer ts.Close()
				parts := strings.Split(ts.Listener.Addr().String(), ":")
				var err error
				port, err = strconv.Atoi(parts[len(parts)-1])
				require.NoError(t, err)
			}

			cmd := app.Project3Cmd{
				CommonArgs: basecli.CommonArgs{
					Dir:       baseclient.WorkDir(tempDir),
					RunCmd:    "echo test",
					Env:       map[string]string{},
					ServerURL: tt.args.serverURL,
				},
				Port:         port,
				DatabaseFile: tempDir + "/" + dbFile,
				CodeDir:      tt.args.codeDir,
				Client:       tt.args.client,
				Stdin:        tt.args.stdin,
				Stdout:       tt.args.stdout,
			}

			err := cmd.Run(basecli.Context{Context: t.Context()})
			tt.wantErr(t, err)
		})
	}
}
