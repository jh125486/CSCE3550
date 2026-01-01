package client_test

import (
	"testing"

	"github.com/jh125486/CSCE3550/pkg/client"
	baseclient "github.com/jh125486/gradebot/pkg/client"
	"github.com/stretchr/testify/assert"
)

func TestExecuteProject1(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{
			name:    "valid port",
			port:    8080,
			wantErr: false, // Won't error because program doesn't actually run
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			cfg := &baseclient.Config{
				Dir:            baseclient.WorkDir(t.TempDir()),
				RunCmd:         "echo test",
				CommandFactory: nil, // nil factory means no actual execution
			}

			err := client.ExecuteProject1(ctx, cfg, tt.port)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestExecuteProject2(t *testing.T) {
	tests := []struct {
		name         string
		port         int
		databaseFile string
		codeDir      string
		wantErr      bool
	}{
		{
			name:         "valid parameters",
			port:         8080,
			databaseFile: "/tmp/test.db",
			codeDir:      ".",
			wantErr:      false, // Won't error because program doesn't actually run
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			cfg := &baseclient.Config{
				Dir:            baseclient.WorkDir(t.TempDir()),
				RunCmd:         "echo test",
				CommandFactory: nil, // nil factory means no actual execution
			}

			err := client.ExecuteProject2(ctx, cfg, tt.port, tt.databaseFile, tt.codeDir)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestExecuteProject3(t *testing.T) {
	tests := []struct {
		name         string
		port         int
		databaseFile string
		codeDir      string
		wantErr      bool
	}{
		{
			name:         "valid parameters",
			port:         8080,
			databaseFile: "/tmp/test.db",
			codeDir:      ".",
			wantErr:      false, // Won't error because program doesn't actually run
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			cfg := &baseclient.Config{
				Dir:            baseclient.WorkDir(t.TempDir()),
				RunCmd:         "echo test",
				CommandFactory: nil, // nil factory means no actual execution
			}

			err := client.ExecuteProject3(ctx, cfg, tt.port, tt.databaseFile, tt.codeDir)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
