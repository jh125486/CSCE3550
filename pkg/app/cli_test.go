package app_test

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/jh125486/CSCE3550/pkg/app"
	basecli "github.com/jh125486/gradebot/pkg/cli"
	baseclient "github.com/jh125486/gradebot/pkg/client"
	"github.com/stretchr/testify/assert"
)

func TestProject1CmdRun(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{
			name:    "successful run",
			port:    8080,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := app.Project1Cmd{
				CommonArgs: basecli.CommonArgs{
					Dir:            baseclient.WorkDir(t.TempDir()),
					RunCmd:         "echo test",
					CommandFactory: nil, // nil means no actual execution
					Client:         &http.Client{},
					ServerURL:      "http://localhost:8080",
					Stdin:          bytes.NewReader([]byte("n\n")), // Don't upload
					Stdout:         &bytes.Buffer{},
				},
				Port: tt.port,
			}

			err := cmd.Run(basecli.Context{Context: t.Context()})
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestProject2CmdRun(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		codeDir string
		wantErr bool
	}{
		{
			name:    "successful run",
			port:    8080,
			codeDir: ".",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			cmd := app.Project2Cmd{
				CommonArgs: basecli.CommonArgs{
					Dir:            baseclient.WorkDir(tempDir),
					RunCmd:         "echo test",
					CommandFactory: nil, // nil means no actual execution
					Client:         &http.Client{},
					ServerURL:      "http://localhost:8080",
					Stdin:          bytes.NewReader([]byte("n\n")), // Don't upload
					Stdout:         &bytes.Buffer{},
				},
				Port:         tt.port,
				DatabaseFile: tempDir + "/test.db",
				CodeDir:      tt.codeDir,
			}

			err := cmd.Run(basecli.Context{Context: t.Context()})
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestProject3CmdRun(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		codeDir string
		wantErr bool
	}{
		{
			name:    "successful run",
			port:    8080,
			codeDir: ".",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			cmd := app.Project3Cmd{
				CommonArgs: basecli.CommonArgs{
					Dir:            baseclient.WorkDir(tempDir),
					RunCmd:         "echo test",
					CommandFactory: nil, // nil means no actual execution
					Client:         &http.Client{},
					ServerURL:      "http://localhost:8080",
					Stdin:          bytes.NewReader([]byte("n\n")), // Don't upload
					Stdout:         &bytes.Buffer{},
				},
				Port:         tt.port,
				DatabaseFile: tempDir + "/test.db",
				CodeDir:      tt.codeDir,
			}

			err := cmd.Run(basecli.Context{Context: t.Context()})
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
