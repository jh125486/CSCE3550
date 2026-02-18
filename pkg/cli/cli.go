package cli

import (
	"github.com/jh125486/CSCE3550/pkg/client"
	basecli "github.com/jh125486/gradebot/pkg/cli"
	baseclient "github.com/jh125486/gradebot/pkg/client"
	"github.com/jh125486/gradebot/pkg/proto/protoconnect"
)

type (
	// CLI defines the command-line interface structure for the gradebot application.
	CLI struct {
		basecli.BaseCLI `embed:""`

		Project1 Project1Cmd `cmd:"" help:"Execute project1 grading client"`
		Project2 Project2Cmd `cmd:"" help:"Execute project2 grading client"`
		Project3 Project3Cmd `cmd:"" help:"Execute project3 grading client"`
	}
	// Project1Cmd defines the command structure for running Project 1 grading.
	Project1Cmd struct {
		basecli.CommonArgs `embed:""`
		PortArg            `embed:""`
	}
	// Project2Cmd defines the command structure for running Project 2 grading.
	Project2Cmd struct {
		basecli.CommonArgs `embed:""`
		CommonProjectArgs  `embed:""`
	}
	// Project3Cmd defines the command structure for running Project 3 grading.
	Project3Cmd struct {
		basecli.CommonArgs `embed:""`
		CommonProjectArgs  `embed:""`
	}

	CommonProjectArgs struct {
		PortArg       `embed:""`
		CodeDirArg    `embed:""`
		DBFileCodeArg `embed:""`
	}
	PortArg struct {
		Port int `default:"8080" help:"Port to check" name:"port" short:"p"`
	}
	CodeDirArg struct {
		CodeDir string `default:"." help:"Path to the source code directory" name:"code-dir"`
	}
	DBFileCodeArg struct {
		DatabaseFile string `default:"totally_not_my_privateKeys.db" help:"Path to the database file" name:"database"`
	}
)

// Run executes the Project 1 grading client.
// The buildID is injected by Kong from the bound value.
func (cmd *Project1Cmd) Run(ctx basecli.Context, svc *basecli.Service) error {
	cfg := &baseclient.Config{
		ServerURL:     cmd.ServerURL,
		WorkDir:       cmd.WorkDir,
		RunCmd:        cmd.RunCmd,
		Env:           cmd.Env,
		QualityClient: protoconnect.NewQualityServiceClient(svc.Client, cmd.ServerURL),
		Reader:        svc.Stdin,
		Writer:        svc.Stdout,
	}
	if cmd.ServerURL != "" {
		cfg.RubricClient = protoconnect.NewRubricServiceClient(svc.Client, cmd.ServerURL)
	}

	return client.ExecuteProject1(ctx, cfg, svc.Client, cmd.Port)
}

// Run executes the Project 2 grading client.
// The buildID is injected by Kong from the bound value.
func (cmd *Project2Cmd) Run(ctx basecli.Context, svc *basecli.Service) error {
	cfg := &baseclient.Config{
		ServerURL:     cmd.ServerURL,
		WorkDir:       cmd.WorkDir,
		RunCmd:        cmd.RunCmd,
		Env:           cmd.Env,
		QualityClient: protoconnect.NewQualityServiceClient(svc.Client, cmd.ServerURL),
		Reader:        svc.Stdin,
		Writer:        svc.Stdout,
	}
	if cmd.ServerURL != "" {
		cfg.RubricClient = protoconnect.NewRubricServiceClient(svc.Client, cmd.ServerURL)
	}

	return client.ExecuteProject2(ctx, cfg, svc.Client, cmd.Port, cmd.DatabaseFile, cmd.CodeDir)
}

// Run executes the Project 3 grading client.
// The buildID is injected by Kong from the bound value.
func (cmd *Project3Cmd) Run(ctx basecli.Context, svc *basecli.Service) error {
	cfg := &baseclient.Config{
		ServerURL:     cmd.ServerURL,
		WorkDir:       cmd.WorkDir,
		RunCmd:        cmd.RunCmd,
		Env:           cmd.Env,
		QualityClient: protoconnect.NewQualityServiceClient(svc.Client, cmd.ServerURL),
		Reader:        svc.Stdin,
		Writer:        svc.Stdout,
	}
	if cmd.ServerURL != "" {
		cfg.RubricClient = protoconnect.NewRubricServiceClient(svc.Client, cmd.ServerURL)
	}

	return client.ExecuteProject3(ctx, cfg, svc.Client, cmd.Port, cmd.DatabaseFile, cmd.CodeDir)
}
