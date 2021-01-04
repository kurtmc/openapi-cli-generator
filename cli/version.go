package cli

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func BuildVersionCommand() (versionCommand *cobra.Command) {
	versionCommand = &cobra.Command{
		Use:   "version",
		Short: "Print the version of the CLI you are running",
		Run: func(cmd *cobra.Command, args []string) {
			logger := log.With().Logger()
			logger.Info().Msg(Root.Version)
		},
	}

	return
}
