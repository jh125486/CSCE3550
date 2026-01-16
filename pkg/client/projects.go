package client

import (
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/jh125486/CSCE3550/pkg/rubrics"
	"github.com/jh125486/gradebot/pkg/client"
	baserubrics "github.com/jh125486/gradebot/pkg/rubrics"
)

var (
	//go:embed instructions/project1.txt
	project1Instructions string
	//go:embed instructions/project2.txt
	project2Instructions string
	//go:embed instructions/project3.txt
	project3Instructions string
)

// resolvePath returns an absolute path. If path is already absolute, it's returned as-is.
// Otherwise, it's joined with basePath to create an absolute path.
func resolvePath(basePath, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(basePath, path)
}

// ExecuteProject1 executes the project1 grading flow using a runtime config.
func ExecuteProject1(ctx context.Context, cfg *client.Config, clientHTTP *http.Client, port int) error {
	bag := make(baserubrics.RunBag)
	baserubrics.SetBagValue(bag, rubrics.EvalContextKey, rubrics.NewEvalContext(fmt.Sprintf("http://127.0.0.1:%d", port),
		rubrics.WithHTTPClient(clientHTTP),
	))

	return client.ExecuteProject(ctx, cfg, "CSCE3550:Project1", project1Instructions, bag,
		rubrics.EvaluateValidJWT,
		rubrics.EvaluateExpiredJWT,
		rubrics.EvaluateHTTPMethods,
		rubrics.EvaluateValidJWKInJWKS,
		rubrics.EvaluateExpiredJWTIsExpired,
		rubrics.EvaluateExpiredJWKNotInJWKS,
	)
}

// ExecuteProject2 executes the project2 grading flow using a runtime config.
func ExecuteProject2(ctx context.Context, cfg *client.Config, clientHTTP *http.Client, port int, databaseFile, codeDir string) error {
	bag := make(baserubrics.RunBag)
	baserubrics.SetBagValue(bag, rubrics.EvalContextKey, rubrics.NewEvalContext(fmt.Sprintf("http://127.0.0.1:%d", port),
		rubrics.WithHTTPClient(clientHTTP),
		rubrics.WithDatabaseFile(resolvePath(cfg.WorkDir.String(), databaseFile)),
		rubrics.WithSrcDir(resolvePath(cfg.WorkDir.String(), codeDir)),
	))

	return client.ExecuteProject(ctx, cfg, "CSCE3550:Project2", project2Instructions, bag,
		rubrics.EvaluateValidJWT,
		rubrics.EvaluateValidJWKInJWKS,
		rubrics.EvaluateDatabaseExists,
		rubrics.EvaluateDatabaseQueryUsesParameters,
	)
}

// ExecuteProject3 executes the project3 grading flow using a runtime config.
func ExecuteProject3(ctx context.Context, cfg *client.Config, clientHTTP *http.Client, port int, databaseFile, codeDir string) error {
	bag := make(baserubrics.RunBag)
	baserubrics.SetBagValue(bag, rubrics.EvalContextKey, rubrics.NewEvalContext(fmt.Sprintf("http://127.0.0.1:%d", port),
		rubrics.WithHTTPClient(clientHTTP),
		rubrics.WithDatabaseFile(resolvePath(cfg.WorkDir.String(), databaseFile)),
		rubrics.WithSrcDir(resolvePath(cfg.WorkDir.String(), codeDir)),
		rubrics.WithUsername("testor_"+uuid.NewString()[0:8]),
	))

	return client.ExecuteProject(ctx, cfg, "CSCE3550:Project3", project3Instructions, bag,
		rubrics.EvaluateTableExists("users", 5),
		rubrics.EvaluateRegistrationWorks,
		rubrics.EvaluatePrivateKeysEncrypted,
		rubrics.EvaluateTableExists("auth_logs", 5),
		rubrics.EvaluateAuthLogging,
		rubrics.EvaluateRateLimiting("/auth", 10),
	)
}
