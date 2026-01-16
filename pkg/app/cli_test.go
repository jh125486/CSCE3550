package app_test

import (
	"bytes"
	"io"
	"net/http"
	"path"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/jh125486/CSCE3550/pkg/app"
	basecli "github.com/jh125486/gradebot/pkg/cli"
	baseclient "github.com/jh125486/gradebot/pkg/client"
	baserubrics "github.com/jh125486/gradebot/pkg/rubrics"
	"github.com/stretchr/testify/require"
)

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

type nopCmd struct{}

func (n *nopCmd) SetDir(string)       {}
func (n *nopCmd) SetStdin(io.Reader)  {}
func (n *nopCmd) SetStdout(io.Writer) {}
func (n *nopCmd) SetStderr(io.Writer) {}
func (n *nopCmd) Start() error        { return nil }
func (n *nopCmd) Run() error          { return nil }
func (n *nopCmd) ProcessKill() error  { return nil }

type nopBuilder struct{}

func (n *nopBuilder) New(_ string, _ ...string) baserubrics.Commander {
	return &nopCmd{}
}

func newTestService() *basecli.Service {
	return &basecli.Service{
		Client:         newMockClient(),
		Stdin:          strings.NewReader("n\n"),
		Stdout:         &bytes.Buffer{},
		CommandBuilder: &nopBuilder{},
	}
}

func TestProject1CmdRun(t *testing.T) {
	t.Parallel()
	type args struct {
		port      int
		serverURL string
		svc       *basecli.Service
	}
	tests := []struct {
		name    string
		args    args
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "success",
			args: args{
				port:      8080,
				serverURL: "http://example.com",
				svc:       newTestService(),
			},
			wantErr: require.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tempDir := t.TempDir()

			cmd := &app.Project1Cmd{
				CommonArgs: basecli.CommonArgs{
					WorkDir:   baseclient.WorkDir(tempDir),
					RunCmd:    "echo test",
					Env:       map[string]string{},
					ServerURL: tt.args.serverURL,
				},
				PortArg: app.PortArg{
					Port: tt.args.port,
				},
			}
			require.NoError(t, kong.ApplyDefaults(cmd))
			ctx := basecli.Context{Context: t.Context()}
			err := cmd.Run(ctx, tt.args.svc)
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
		svc          *basecli.Service
	}
	tests := []struct {
		name    string
		args    args
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "success",
			args: args{
				port:         8080,
				codeDir:      ".",
				databaseFile: "test.db",
				serverURL:    "http://example.com",
				svc:          newTestService(),
			},
			wantErr: require.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tempDir := t.TempDir()

			cmd := &app.Project2Cmd{
				CommonArgs: basecli.CommonArgs{
					WorkDir:   baseclient.WorkDir(tempDir),
					RunCmd:    "echo test",
					Env:       map[string]string{},
					ServerURL: tt.args.serverURL,
				},
				PortArg: app.PortArg{
					Port: tt.args.port,
				},
				DBFileCodeArg: app.DBFileCodeArg{
					DatabaseFile: path.Join(tempDir, tt.args.databaseFile),
				},
				CodeDirArg: app.CodeDirArg{
					CodeDir: tt.args.codeDir,
				},
			}
			require.NoError(t, kong.ApplyDefaults(cmd))
			ctx := basecli.Context{Context: t.Context()}
			err := cmd.Run(ctx, tt.args.svc)
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
		svc          *basecli.Service
	}
	tests := []struct {
		name    string
		args    args
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "success",
			args: args{
				port:         8080,
				codeDir:      ".",
				databaseFile: "test.db",
				serverURL:    "http://example.com",
				svc:          newTestService(),
			},
			wantErr: require.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cmd := &app.Project3Cmd{
				CommonArgs: basecli.CommonArgs{
					WorkDir:   baseclient.WorkDir(t.TempDir()),
					RunCmd:    "echo test",
					Env:       map[string]string{},
					ServerURL: tt.args.serverURL,
				},
				PortArg: app.PortArg{
					Port: tt.args.port,
				},
				DBFileCodeArg: app.DBFileCodeArg{
					DatabaseFile: path.Join(t.TempDir(), tt.args.databaseFile),
				},
				CodeDirArg: app.CodeDirArg{
					CodeDir: tt.args.codeDir,
				},
			}

			require.NoError(t, kong.ApplyDefaults(cmd))
			ctx := basecli.Context{Context: t.Context()}
			err := cmd.Run(ctx, tt.args.svc)
			tt.wantErr(t, err)
		})
	}
}
