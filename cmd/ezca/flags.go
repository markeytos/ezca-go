package main

import "github.com/spf13/pflag"

var (
	outputFileFlag      string
	listAuthoritiesFlag bool

	// CA Info
	authorityIDFlag string
	templateIDFlag  string

	/// Certificate Information
	// Certificate Subject Name Values
	snCommonNameFlag         string
	snSerialNumberFlag       string
	snCountryFlag            []string
	snOrganizationFlag       []string
	snOrganizationalUnitFlag []string
	snLocalityFlag           []string
	snProvinceFlag           []string
	snStreetAddressFlag      []string
	snPostalCodeFlag         []string
	// Certificate Subject Alternate Names
	sanDNSFlag   []string
	sanEmailFlag []string
	sanIPFlag    []string
	sanURIsFlag  []string

	// Sign options
	subjectNameFlag       string
	durationFlag          string
	keyUsagesFlag         []string
	extendedKeyUsagesFlag []string
)

func addOutputFileFlag(fset *pflag.FlagSet) string {
	const name = "output-file"
	fset.StringVarP(&outputFileFlag, name, "o", "out.cer", "Output file name, creates it if it does not exist and overwrite if it does")
	return name
}

func addListAuthoritiesFlag(fset *pflag.FlagSet) string {
	const name = "list-authorities"
	fset.BoolVarP(&listAuthoritiesFlag, name, "l", false, "List certificate authorities")
	return name
}

func addAuthorityIDFlag(fset *pflag.FlagSet) string {
	const name = "authority-id"
	fset.StringVarP(&authorityIDFlag, name, "A", "", "EZCA authority ID")
	return name
}

func addTemplateIDFlag(fset *pflag.FlagSet) string {
	const name = "template-id"
	fset.StringVarP(&templateIDFlag, name, "T", "", "EZCA authority's template ID")
	return name
}

func addCertificateNameInformationFlags(fset *pflag.FlagSet) {
	fset.StringVar(&snCommonNameFlag, "cert-sn-common-name", "", "Certificate Subject Common Name")
	fset.StringVar(&snSerialNumberFlag, "cert-sn-serial-number", "", "Certificate Subject Serial Number")
	fset.StringSliceVar(&snCountryFlag, "cert-sn-country", nil, "Certificate Subject Country")
	fset.StringSliceVar(&snOrganizationFlag, "cert-sn-organization", nil, "Certificate Subject Organization")
	fset.StringSliceVar(&snOrganizationalUnitFlag, "cert-sn-organizational-unit", nil, "Certificate Subject Organizational Unit")
	fset.StringSliceVar(&snLocalityFlag, "cert-sn-locality", nil, "Certificate Subject Locality")
	fset.StringSliceVar(&snProvinceFlag, "cert-sn-province", nil, "Certificate Subject Province")
	fset.StringSliceVar(&snStreetAddressFlag, "cert-sn-street-address", nil, "Certificate Subject Street Address")
	fset.StringSliceVar(&snPostalCodeFlag, "cert-sn-postal-code", nil, "Certificate Subject Postal Code")

	fset.StringSliceVar(&sanDNSFlag, "cert-san-dns", nil, "Certificate Subject Alternate Name DNS")
	fset.StringSliceVar(&sanEmailFlag, "cert-san-email", nil, "Certificate Subject Alternate Name Email")
	fset.StringSliceVar(&sanIPFlag, "cert-san-ip", nil, "Certificate Subject Alternate Name IP Address")
	fset.StringSliceVar(&sanURIsFlag, "cert-san-uri", nil, "Certificate Subject Alternate Name URIs")
}

func addSignOptionsFlags(fset *pflag.FlagSet) {
	fset.StringVar(&subjectNameFlag, "sign-overwrite-subject-name", "", "Subject Name to overwrite in signing process")
	fset.StringVar(&durationFlag, "sign-cert-duration", "2160h", "Signed certificate validity duration, valid units are \"ns\", \"us\", \"ms\", \"s\", \"m\", \"h\"")
	fset.StringSliceVar(&keyUsagesFlag, "sign-key-usages", nil, "Certificate key usages (default [\"Key Encipherment\", \"Digital Signature\"])")
	fset.StringSliceVar(&extendedKeyUsagesFlag, "sign-ext-key-usages", nil, "Certificate extended key usages (default [\"1.3.6.1.5.5.7.3.1\", \"1.3.6.1.5.5.7.3.2\"])")
}
