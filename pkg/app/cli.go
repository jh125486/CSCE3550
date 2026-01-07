package app

import (
	"github.com/jh125486/CSCE3550/pkg/client"
	basecli "github.com/jh125486/gradebot/pkg/cli"
	baseclient "github.com/jh125486/gradebot/pkg/client"
	"github.com/jh125486/gradebot/pkg/proto/protoconnect"
	"github.com/jh125486/gradebot/pkg/rubrics"
)

type (
	// CLI defines the command-line interface structure for the gradebot application.
	CLI struct {
		Project1 Project1Cmd `cmd:"" help:"Execute project1 grading client"`
		Project2 Project2Cmd `cmd:"" help:"Execute project2 grading client"`
		Project3 Project3Cmd `cmd:"" help:"Execute project3 grading client"`
	}
	// Project1Cmd defines the command structure for running Project 1 grading.
	Project1Cmd struct {
		basecli.CommonArgs
		Port int `default:"8080" help:"Port to check" name:"port" short:"p"`
	}
	// Project2Cmd defines the command structure for running Project 2 grading.
	Project2Cmd struct {
		basecli.CommonArgs
		Port         int    `default:"8080"                          help:"Port to check"                     name:"port"     short:"p"`
		DatabaseFile string `default:"totally_not_my_privateKeys.db" help:"Path to the database file"         name:"database"`
		CodeDir      string `default:"."                             help:"Path to the source code directory" name:"code-dir"`
	}
	// Project3Cmd defines the command structure for running Project 3 grading.
	Project3Cmd struct {
		basecli.CommonArgs
		Port         int    `default:"8080"                          help:"Port to check"                     name:"port"     short:"p"`
		DatabaseFile string `default:"totally_not_my_privateKeys.db" help:"Path to the database file"         name:"database"`
		CodeDir      string `default:"."                             help:"Path to the source code directory" name:"code-dir"`
	}
)

// Run executes the Project 1 grading client.
func (cmd *Project1Cmd) Run(ctx basecli.Context) error {
	cfg := &baseclient.Config{
		ServerURL:     cmd.ServerURL,
		Dir:           cmd.Dir,
		RunCmd:        cmd.RunCmd,
		QualityClient: protoconnect.NewQualityServiceClient(cmd.Client, cmd.ServerURL),
		Reader:        cmd.Stdin,
		Writer:        cmd.Stdout,
		CommandFactory: &rubrics.ExecCommandFactory{
			Context: ctx,
			Env:     cmd.Env,
		},
	}

	// Only set RubricClient if a server URL is provided
	if cmd.ServerURL != "" {
		cfg.RubricClient = protoconnect.NewRubricServiceClient(cmd.Client, cmd.ServerURL)
	}

	return client.ExecuteProject1(ctx, cfg, cmd.Port)
}

// Run executes the Project 2 grading client.
func (cmd *Project2Cmd) Run(ctx basecli.Context) error {
	cfg := &baseclient.Config{
		ServerURL:     cmd.ServerURL,
		Dir:           cmd.Dir,
		RunCmd:        cmd.RunCmd,
		QualityClient: protoconnect.NewQualityServiceClient(cmd.Client, cmd.ServerURL),
		Reader:        cmd.Stdin,
		Writer:        cmd.Stdout,
		CommandFactory: &rubrics.ExecCommandFactory{
			Context: ctx,
			Env:     cmd.Env,
		},
	}

	// Only set RubricClient if a server URL is provided
	if cmd.ServerURL != "" {
		cfg.RubricClient = protoconnect.NewRubricServiceClient(cmd.Client, cmd.ServerURL)
	}

	return client.ExecuteProject2(ctx, cfg, cmd.Port, cmd.DatabaseFile, cmd.CodeDir)
}

// Run executes the Project 3 grading client.
func (cmd *Project3Cmd) Run(ctx basecli.Context) error {
	cfg := &baseclient.Config{
		ServerURL:     cmd.ServerURL,
		Dir:           cmd.Dir,
		RunCmd:        cmd.RunCmd,
		QualityClient: protoconnect.NewQualityServiceClient(cmd.Client, cmd.ServerURL),
		Reader:        cmd.Stdin,
		Writer:        cmd.Stdout,
		CommandFactory: &rubrics.ExecCommandFactory{
			Context: ctx,
			Env:     cmd.Env,
		},
	}

	// Only set RubricClient if a server URL is provided
	if cmd.ServerURL != "" {
		cfg.RubricClient = protoconnect.NewRubricServiceClient(cmd.Client, cmd.ServerURL)
	}

	return client.ExecuteProject3(ctx, cfg, cmd.Port, cmd.DatabaseFile, cmd.CodeDir)
}
