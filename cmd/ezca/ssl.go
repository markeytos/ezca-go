package main

import (
	"errors"

	"github.com/spf13/cobra"
)

var (
	certificateFlag string
	thumbprintFlag  string
)

var sslCmd = &cobra.Command{
	Use:   "ssl",
	Short: "Manage SSL Certificate Authorities and Certificates",
	RunE: func(cmd *cobra.Command, args []string) error {
		if listAuthoritiesFlag {
			return sslListAuthorities(cmd.Context())
		}
		return cmd.Help()
	},
}

var sslGenerateCertificateCmd = &cobra.Command{
	Use:     "generate-certificate --authority-id UUID --template-id UUID",
	Aliases: []string{"gen-cert", "gencert"},
	Short:   "Sign certificate signing requests (CSRs)",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return sslGenerateCertifcate(cmd.Context())
	},
}

var sslSignCmd = &cobra.Command{
	Use:   "sign --authority-id UUID --template-id UUID PATH",
	Short: "Sign certificate signing requests (CSRs)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return sslSign(cmd.Context(), args[0])
	},
}

var sslRevokeCmd = &cobra.Command{
	Use:   "revoke --authority-id UUID --template-id UUID (--certificate PATH | --thumbprint THUMBPRINT)",
	Short: "Revoke certificate signing requests (CSRs)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if certificateFlag != "" {
			return sslRevokeWithCertificate(cmd.Context(), certificateFlag)
		}
		if thumbprintFlag != "" {
			return sslRevokeWithThumbprint(cmd.Context(), thumbprintFlag)
		}
		return errors.New("unreachable as certificate or thumbprint must be set")
	},
}

func init() {
	addListAuthoritiesFlag(sslCmd.Flags())

	addOutputFileFlag(sslGenerateCertificateCmd.Flags())
	sslGenerateCertificateCmd.MarkFlagRequired(addAuthorityIDFlag(sslGenerateCertificateCmd.Flags())) //nolint:errcheck // Marking flag as required.
	sslGenerateCertificateCmd.MarkFlagRequired(addTemplateIDFlag(sslGenerateCertificateCmd.Flags()))  //nolint:errcheck // Marking flag as required.
	addCertificateNameInformationFlags(sslGenerateCertificateCmd.Flags())
	addSignOptionsFlags(sslGenerateCertificateCmd.Flags())
	sslCmd.AddCommand(sslGenerateCertificateCmd)

	addOutputFileFlag(sslSignCmd.Flags())
	sslSignCmd.MarkFlagRequired(addAuthorityIDFlag(sslSignCmd.Flags())) //nolint:errcheck // Marking flag as required.
	sslSignCmd.MarkFlagRequired(addTemplateIDFlag(sslSignCmd.Flags()))  //nolint:errcheck // Marking flag as required.
	addCertificateNameInformationFlags(sslSignCmd.Flags())
	addSignOptionsFlags(sslSignCmd.Flags())
	sslCmd.AddCommand(sslSignCmd)

	sslRevokeCmd.MarkFlagRequired(addAuthorityIDFlag(sslRevokeCmd.Flags())) //nolint:errcheck // Marking flag as required.
	sslRevokeCmd.MarkFlagRequired(addTemplateIDFlag(sslRevokeCmd.Flags()))  //nolint:errcheck // Marking flag as required.
	sslRevokeCmd.Flags().StringVarP(&thumbprintFlag, "thumbprint", "t", "", "Certificate thumbprint (SHA1 sum of raw contents)")
	sslRevokeCmd.Flags().StringVarP(&certificateFlag, "certificate", "c", "", "Certificate file path, in PEM format")
	sslRevokeCmd.MarkFlagsOneRequired("thumbprint", "certificate")
	sslRevokeCmd.MarkFlagsMutuallyExclusive("thumbprint", "certificate")
	sslCmd.AddCommand(sslRevokeCmd)
}
