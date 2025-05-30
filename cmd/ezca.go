package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/google/uuid"
	"github.com/markeytos/ezca-go"
)

func main() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		panic(err)
	}

	client, err := ezca.NewClient("https://eastus.g.testslot.ezca.io/", cred)
	if err != nil {
		panic(err)
	}

	println("ALL CAs")
	cas, err := client.ListAuthorities(context.TODO())
	if err != nil {
		panic(err)
	}
	for _, ca := range cas {
		fmt.Printf("%s - %s\n", ca.ID, ca.FriendlyName)
	}

	println()
	println("SSL CAs")
	ssls, err := client.ListSSLAuthorities(context.TODO())
	if err != nil {
		panic(err)
	}
	for _, ca := range ssls {
		fmt.Printf("%s | %s - %s \n", ca.ID, ca.TemplateID, ca.FriendlyName)
	}

	println()
	println("Sign")
	sslCA := ezca.NewSSLAuthority(uuid.MustParse("2eb8b71e-62a6-46bd-a41b-f010defa8327"), uuid.MustParse("dc5fc2a9-edf9-481f-a2c6-9db1d54c026f"))
	sslClient := ezca.NewSSLAuthorityClient(client, sslCA)

	asn1KeyUsage, _ := asn1.Marshal(asn1.BitString{Bytes: []byte{byte(x509.KeyUsageDigitalSignature)}, BitLength: 8})
	cr := &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"Keytos Test"},
			CommonName:   "keytos.test",
		},
		DNSNames: []string{"keytos.test"},
		Extensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{2, 5, 29, 15},
				Value: asn1KeyUsage,
			},
		},
	}
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, cr, privateKey)

	certChain, err := sslClient.Sign(context.TODO(), csr, &ezca.SignOptions{
		SourceTag: "Test",
	})
	if err != nil {
		panic(err)
	}

	for _, cer := range certChain {
		fmt.Printf("%s | %s <- %s\n", cer.SerialNumber, cer.Subject.String(), cer.Issuer.String())
	}

	println()
	println("Revoke")
	err = sslClient.Revoke(context.TODO(), certChain[0])
	if err != nil {
		panic(err)
	}
	println("Successful revoke")
	//
	// println()
	// println("Old CSR")
	// fmt.Printf("subject name: %s\n", cr.Subject.String())
	// fmt.Printf("dns names: %s\n", strings.Join(cr.DNSNames, ", "))
	// err := cr.CheckSignature()
	// fmt.Printf("sig: %v\n", err)
	// println("CSR")
	// parsedCSR, err := x509.ParseCertificateRequest(csr)
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Printf("subject name: %s\n", parsedCSR.Subject.String())
	// fmt.Printf("dns names: %s\n", strings.Join(parsedCSR.DNSNames, ", "))
	// err = parsedCSR.CheckSignature()
	// fmt.Printf("sig: %v\n", err)
}
