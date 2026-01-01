package client

import (
	"context"
	_ "embed" // embed rubric files
	"fmt"

	"github.com/google/uuid"
	"github.com/jh125486/CSCE3550/pkg/rubrics"
	"github.com/jh125486/gradebot/pkg/client"
	baserubrics "github.com/jh125486/gradebot/pkg/rubrics"
)

var (
	_ string // placeholder for future embed usage
)

// ExecuteProject1 executes the project1 grading flow using a runtime config.
func ExecuteProject1(ctx context.Context, cfg *client.Config, port int) error {
	// Initialize eval context in bag
	bag := make(baserubrics.RunBag)
	bag["evalContext"] = &rubrics.EvalContext{
		HostURL: fmt.Sprintf("http://127.0.0.1:%d", port),
	}

	// Create program runner for student's project
	program := baserubrics.NewProgram(cfg.Dir.String(), cfg.RunCmd, cfg.CommandFactory)
	defer func() { _ = program.Cleanup(ctx) }()

	results := baserubrics.NewResult("CSCE3550:Project1")

	evaluators := []baserubrics.Evaluator{
		rubrics.EvaluateValidJWT,
		rubrics.EvaluateExpiredJWT,
		rubrics.EvaluateHTTPMethods,
		rubrics.EvaluateValidJWKInJWKS,
		rubrics.EvaluateExpiredJWTIsExpired,
		rubrics.EvaluateExpiredJWKNotInJWKS,
	}

	for _, evaluator := range evaluators {
		results.Rubric = append(results.Rubric, evaluator(ctx, program, bag))
	}

	// Print rubric table
	results.Render(cfg.Writer)

	// Optionally upload results
	if cfg.RubricClient != nil && client.PromptForSubmission(ctx, cfg.Writer, cfg.Reader) {
		if err := cfg.UploadResult(ctx, results); err != nil {
			return fmt.Errorf("failed to upload result: %w", err)
		}
	}

	return nil
}

// ExecuteProject2 executes the project2 grading flow using a runtime config.
func ExecuteProject2(ctx context.Context, cfg *client.Config, port int, databaseFile, codeDir string) error {
	// Initialize eval context in bag
	bag := make(baserubrics.RunBag)
	bag["evalContext"] = &rubrics.EvalContext{
		HostURL:      fmt.Sprintf("http://127.0.0.1:%d", port),
		DatabaseFile: databaseFile,
		SrcDir:       codeDir,
	}

	// Create program runner for student's project
	program := baserubrics.NewProgram(cfg.Dir.String(), cfg.RunCmd, cfg.CommandFactory)
	defer func() { _ = program.Cleanup(ctx) }()

	results := baserubrics.NewResult("CSCE3550:Project2")

	evaluators := []baserubrics.Evaluator{
		rubrics.EvaluateValidJWT,
		rubrics.EvaluateValidJWKInJWKS,
		rubrics.EvaluateDatabaseExists,
		rubrics.EvaluateDatabaseQueryUsesParameters,
	}

	for _, evaluator := range evaluators {
		results.Rubric = append(results.Rubric, evaluator(ctx, program, bag))
	}

	// Print rubric table
	results.Render(cfg.Writer)

	// Optionally upload results
	if cfg.RubricClient != nil && client.PromptForSubmission(ctx, cfg.Writer, cfg.Reader) {
		if err := cfg.UploadResult(ctx, results); err != nil {
			return fmt.Errorf("failed to upload result: %w", err)
		}
	}

	return nil
}

// ExecuteProject3 executes the project3 grading flow using a runtime config.
func ExecuteProject3(ctx context.Context, cfg *client.Config, port int, databaseFile, codeDir string) error {
	// Initialize eval context in bag
	username := "testor_" + uuid.NewString()[0:8]
	bag := make(baserubrics.RunBag)
	bag["evalContext"] = &rubrics.EvalContext{
		HostURL:      fmt.Sprintf("http://127.0.0.1:%d", port),
		DatabaseFile: databaseFile,
		SrcDir:       codeDir,
		Username:     username,
	}

	// Create program runner for student's project
	program := baserubrics.NewProgram(cfg.Dir.String(), cfg.RunCmd, cfg.CommandFactory)
	defer func() { _ = program.Cleanup(ctx) }()

	results := baserubrics.NewResult("CSCE3550:Project3")

	evaluators := []baserubrics.Evaluator{
		rubrics.EvaluateTableExists("users", 5),
		rubrics.EvaluateRegistrationWorks,
		rubrics.EvaluatePrivateKeysEncrypted,
		rubrics.EvaluateTableExists("auth_logs", 5),
		rubrics.EvaluateAuthLogging,
		rubrics.EvaluateRateLimiting("/auth", 10),
	}

	for _, evaluator := range evaluators {
		results.Rubric = append(results.Rubric, evaluator(ctx, program, bag))
	}

	// Print rubric table
	results.Render(cfg.Writer)

	// Optionally upload results
	if cfg.RubricClient != nil && client.PromptForSubmission(ctx, cfg.Writer, cfg.Reader) {
		if err := cfg.UploadResult(ctx, results); err != nil {
			return fmt.Errorf("failed to upload result: %w", err)
		}
	}

	return nil
}
