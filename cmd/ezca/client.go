package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/google/uuid"
	"github.com/markeytos/ezca-go"
)

func defaultClient() (*ezca.Client, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, err
	}
	return ezca.NewClient(ezcaURLFlag, cred)
}

func listAuthorities(ctx context.Context) error {
	client, err := defaultClient()
	if err != nil {
		return err
	}

	cas, err := client.ListAuthorities(ctx)
	if err != nil {
		return err
	}

	if jsonOutputFlag {
		return printJson(cas)
	}

	records := make([][]string, len(cas))
	for i, ca := range cas {
		records[i] = []string{ca.ID.String(), ca.FriendlyName}
	}
	return printTable([]string{"Authority ID", "Friendly Name"}, records)
}

func sslListAuthorities(ctx context.Context) error {
	client, err := defaultClient()
	if err != nil {
		return err
	}

	cas, err := client.ListSSLAuthorities(ctx)
	if err != nil {
		return err
	}

	if jsonOutputFlag {
		return printJson(cas)
	}

	records := make([][]string, len(cas))
	for i, ca := range cas {
		records[i] = []string{ca.ID.String(), ca.TemplateID.String(), ca.FriendlyName}
	}
	return printTable([]string{"Authority ID", "Template ID", "Friendly Name"}, records)
}

func defaultSSLAuthorityClient() (*ezca.SSLAuthorityClient, error) {
	client, err := defaultClient()
	if err != nil {
		return nil, err
	}
	caid, err := uuid.Parse(authorityIDFlag)
	if err != nil {
		return nil, fmt.Errorf("invalid authority ID: must be a UUID: %s", authorityIDFlag)
	}
	temID, err := uuid.Parse(templateIDFlag)
	if err != nil {
		return nil, fmt.Errorf("invalid authority ID: must be a UUID: %s", authorityIDFlag)
	}
	return ezca.NewSSLAuthorityClient(client, ezca.NewSSLAuthority(caid, temID))
}

func sslGenerateCertifcate(ctx context.Context) (err error) {
	// create CSR
	var ipaddresses []net.IP
	if len(sanIPFlag) > 0 {
		ipaddresses = make([]net.IP, len(sanIPFlag))
		for i, ip := range sanIPFlag {
			ipaddresses[i] = net.ParseIP(ip)
			if ipaddresses[i] == nil {
				return fmt.Errorf("invalid IP adress: %s", ip)
			}
		}
	}
	var uris []*url.URL
	if len(sanURIsFlag) > 0 {
		uris = make([]*url.URL, len(sanURIsFlag))
		for i, uri := range sanURIsFlag {
			puri, err := url.Parse(uri)
			if err != nil {
				return fmt.Errorf("invalid URI: %s", uri)
			}
			uris[i] = puri
		}
	}
	cr := &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:            snCountryFlag,
			Organization:       snOrganizationFlag,
			OrganizationalUnit: snOrganizationalUnitFlag,
			Locality:           snLocalityFlag,
			Province:           snProvinceFlag,
			StreetAddress:      snStreetAddressFlag,
			PostalCode:         snPostalCodeFlag,
			SerialNumber:       snSerialNumberFlag,
			CommonName:         snCommonNameFlag,
		},
		DNSNames:        sanDNSFlag,
		EmailAddresses:  sanEmailFlag,
		IPAddresses:     ipaddresses,
		URIs:            uris,
		ExtraExtensions: nil,
	}

	// TODO: make algorithm configurable, default to RSA 2048
	// https://github.com/markeytos/ezca-go/issues/1
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	csr, err := x509.CreateCertificateRequest(rand.Reader, cr, privateKey)
	if err != nil {
		return fmt.Errorf("could not create csr: %v", err)
	}

	cert, err := commonSSLSignCSR(ctx, csr)
	if err != nil {
		return err
	}

	// save certificate
	f, err := os.OpenFile(outputFileFlag, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0400)
	if err != nil {
		return fmt.Errorf("could not open nor create file: %s: %v", outputFileFlag, err)
	}
	defer func() {
		ferr := f.Close()
		if err == nil {
			err = fmt.Errorf("file close error: %s: %v", outputFileFlag, ferr)
		}
	}()

	var writeErrs []error
	err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	writeErrs = append(writeErrs, err)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	writeErrs = append(writeErrs, err)
	if err == nil {
		err = pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes})
		writeErrs = append(writeErrs, err)
	}
	err = errors.Join(writeErrs...)
	if err != nil {
		return fmt.Errorf("errors saving new certificate: %s: %v", outputFileFlag, err)
	}
	return
}

func sslSign(ctx context.Context, csrPath string) (err error) {
	// get CSR from file
	csr, err := bytesFromPEMFile(csrPath, "CERTIFICATE REQUEST")
	if err != nil {
		return err
	}

	cert, err := commonSSLSignCSR(ctx, csr)
	if err != nil {
		return err
	}

	// save certificate
	f, err := os.OpenFile(outputFileFlag, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0400)
	if err != nil {
		return fmt.Errorf("could not open nor create file: %s: %v", outputFileFlag, err)
	}
	defer func() {
		ferr := f.Close()
		if err == nil {
			err = fmt.Errorf("file close error: %s: %v", outputFileFlag, ferr)
		}
	}()

	err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err != nil {
		return fmt.Errorf("errors saving new certificate: %s: %v", outputFileFlag, err)
	}
	return
}

func commonSSLSignCSR(ctx context.Context, csr []byte) (*x509.Certificate, error) {
	client, err := defaultSSLAuthorityClient()
	if err != nil {
		return nil, err
	}

	duration, err := time.ParseDuration(durationFlag)
	if err != nil {
		return nil, fmt.Errorf("invalid duration: %s", durationFlag)
	}
	var keyUsages []ezca.KeyUsage
	if len(keyUsagesFlag) > 0 {
		keyUsages = make([]ezca.KeyUsage, len(keyUsagesFlag))
		for i, ku := range keyUsagesFlag {
			keyUsages[i] = ezca.KeyUsage(ku)
		}
	}
	var extendedKeyUsages []ezca.ExtKeyUsage
	if len(extendedKeyUsagesFlag) > 0 {
		extendedKeyUsages = make([]ezca.ExtKeyUsage, len(extendedKeyUsagesFlag))
		for i, eku := range extendedKeyUsagesFlag {
			extendedKeyUsages[i] = ezca.ExtKeyUsage(eku)
		}
	}

	opts := &ezca.SignOptions{
		SourceTag:         "EZCA Go CLI",
		Duration:          duration,
		KeyUsages:         keyUsages,
		ExtendedKeyUsages: extendedKeyUsages,
		SubjectName:       subjectNameFlag,
	}

	cert, err := client.Sign(ctx, csr, opts)
	if err != nil {
		return nil, fmt.Errorf("ezca csr sign error: %v", err)
	}
	return cert[0], nil
}

func sslRevokeWithThumbprint(ctx context.Context, thumbprintStr string) error {
	// get CSR from file
	var thumbprint [20]byte
	n, err := hex.Decode(thumbprint[:], []byte(thumbprintStr))
	if err != nil {
		return fmt.Errorf("invalid thumbprint: %v", err)
	}
	if n != 20 {
		return errors.New("thumbprint must be 20 bytes (40 hex characters)")
	}

	client, err := defaultSSLAuthorityClient()
	if err != nil {
		return err
	}

	err = client.RevokeWithThumbprint(ctx, thumbprint)
	if err != nil {
		return fmt.Errorf("ezca revoke error: %v", err)
	}
	return nil
}

func sslRevokeWithCertificate(ctx context.Context, certPath string) error {
	// get CSR from file
	certBytes, err := bytesFromPEMFile(certPath, "CERTIFICATE")
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("invalid certificate: %s: %v", certPath, err)
	}

	client, err := defaultSSLAuthorityClient()
	if err != nil {
		return err
	}

	err = client.Revoke(ctx, cert)
	if err != nil {
		return fmt.Errorf("ezca revoke error: %v", err)
	}
	return nil
}

func printJson(v any) error {
	jsonStr, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(os.Stdout, string(jsonStr))
	return err
}

func printTable(headers []string, records [][]string) error {
	if len(headers) == 0 {
		return errors.New("ezca cmd: no headers passed")
	}

	columnWidths := make([]int, len(headers))
	for i, header := range headers {
		columnWidths[i] = len(header)
	}
	for _, row := range records {
		if len(headers) != len(row) {
			return errors.New("ezca cmd: data row and headers have differnet number of columns")
		}
		for i, col := range row {
			columnWidths[i] = max(columnWidths[i], len(col))
		}
	}

	var b strings.Builder
	_, err := fmt.Fprintf(&b, "%%-%ds", columnWidths[0])
	if err != nil {
		return err
	}
	for _, w := range columnWidths[1:] {
		_, err = fmt.Fprintf(&b, "\t%%-%ds", w)
		if err != nil {
			return err
		}
	}
	b.WriteRune('\n')
	fmtStr := b.String()
	b.Reset()

	fmt.Fprintf(&b, fmtStr, convertToAny(headers)...)
	for _, row := range records {
		fmt.Fprintf(&b, fmtStr, convertToAny(row)...)
	}
	fmt.Print(b.String())

	return nil
}

func convertToAny[T any](vs []T) []any {
	arr := make([]any, len(vs))
	for i, v := range vs {
		arr[i] = any(v)
	}
	return arr
}

func bytesFromPEMFile(path, pemType string) ([]byte, error) {
	csrBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read file: %s: %v", path, err)
	}
	var b *pem.Block
	var csrBlock *pem.Block
	for csrBlock == nil && len(csrBytes) > 0 {
		b, csrBytes = pem.Decode(csrBytes)
		if b == nil {
			return nil, fmt.Errorf("failed to decode PEM from file: %s: %v", path, err)
		}
		if b.Type == pemType {
			csrBlock = b
		}
	}
	return b.Bytes, nil
}
