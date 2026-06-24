// Command magpie is the CLI for the collection pipeline.
package main

import (
	"os"

	"github.com/ezequielcamezzana/magpie/cmd/magpie/commands"

	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:          "magpie",
		Short:        "SCA server: collect, match and serve vulnerability data",
		SilenceUsage: true,
	}

	root.AddCommand(
		commands.NewVersionCmd(),
		commands.NewServerCmd(),
		commands.NewDeleteCmd(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
