package main

import "github.com/spf13/cobra"

var (
	ezcaURLFlag    string
	jsonOutputFlag bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "ezca",
	Short: "A CLI for EZCA",
	Long: `ezca is a command-line interface that helps you manage your
Certificate Authorities, and generate and revoke certificates.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if listAuthoritiesFlag {
			return listAuthorities(cmd.Context())
		}
		return cmd.Help()
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&ezcaURLFlag, "ezca-url", "U", "https://portal.ezca.io/", "EZCA instance URL")
	rootCmd.PersistentFlags().BoolVarP(&jsonOutputFlag, "json-output", "J", false, "Output JSON for listing commands")

	addListAuthoritiesFlag(rootCmd.Flags())

	rootCmd.AddCommand(sslCmd)
}
