package ezca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/markeytos/ezca-go/internal/testshared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testSSLAuthority = NewSSLAuthority(uuid.Nil, uuid.Nil)

func TestSign(t *testing.T) {
	t.Run("invalid csr", func(t *testing.T) {
		c := sslAuthorityClient(nil)
		certs, err := c.Sign(t.Context(), []byte{}, nil)
		require.ErrorContains(t, err, "asn1:")
		assert.Empty(t, certs)
	})

	cr := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test",
		},
		DNSNames: []string{"test.ezca.io"},
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	csr, err := x509.CreateCertificateRequest(rand.Reader, cr, privateKey)
	require.NoError(t, err)

	// these collec
	leafCert, err := x509.ParseCertificate(getBytesFromBase64(t, "MIIDrTCCApWgAwIBAgIUGPvTTixX6hCWbhl8h2VUvC1GNiQwDQYJKoZIhvcNAQELBQAwajELMAkGA1UEBhMCVVMxFjAUBgNVBAgMDU1hc3NhY2h1c2V0dHMxDzANBgNVBAcMBkJvc3RvbjEPMA0GA1UECgwGS2V5dG9zMSEwHwYDVQQLDBhJbnRlcm1lZGlhdGUgQ2VydGlmaWNhdGUwHhcNMjUwNjA1MDE0MTE0WhcNMjYwNjA1MDE0MTE0WjBiMQswCQYDVQQGEwJVUzEWMBQGA1UECAwNTWFzc2FjaHVzZXR0czEPMA0GA1UEBwwGQm9zdG9uMQ8wDQYDVQQKDAZLZXl0b3MxGTAXBgNVBAsMEExlYWYgQ2VydGlmaWNhdGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDK84U1UMIa/BwFwJ3tqyftAw0lBQX+K8pOvnunmDV1LweFLpArtO46fYQ8VhoE4z7BjIgaU/Spy5AJQ6wW5P7W17PBRO0Bj9HGmgEtI4o3S5jgmAgPMCi9x1BJRyYtnC3WENrrOKX65zEa37NGtdhUwQfDDK+fOUGpem9r/YQBj/ND0X92NG1XJ/zgAWrnKtKYDIUtLp+AmjKkEaMJHSudeu4j5ceC2qHi8qQQJXNSzMjd92zqcIVrZbQziWILfsqKiCBd87/cggB88ZTCA55+LOSaTpj5i7e81gTHwpe/Ul5YszsL5CpY2o3E7uVbBVCbOuGGAWX04fAXQDPRfxiXAgMBAAGjUzBRMB0GA1UdDgQWBBT1hDktlLs/V5y3b/GljpA293qF9DAfBgNVHSMEGDAWgBRKu2Yzi8JcgSuUAIttVnXLeZlrEDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAyF7i73r7j8844SgcYGAqpKbnJh0u34waWXnLWPb/4DVffKhgJccAUYAOUi6pzxtZg7pCWJKumk4K6RLmH69L1O/UBvVEfqOCoUZ3yz0bRVPUvYmlObbVyR9GddQifaGKxyZvpbfns1OcuOiNdOhgFV9khrkUodludQCxFvAQjrI02NiVHrMw53Z7qvEW61P7HvSAkQHSI80ANsIgiSmEoJoHYsHgkBnYrca7wuWTSaAno2VIgM6iB8+n3SXXOWsLKB7lnXM+Yjzi5oqxV4earsBxn9+NwSWrims9V52M0hMUaG20SMUyIqPb8KAmVdptYbHDzqj9A6kH1KU+bgRR5"))
	require.NoError(t, err)
	issuCert, err := x509.ParseCertificate(getBytesFromBase64(t, "MIIDqjCCApKgAwIBAgIUb8Y0RdftFQp+gzwyc4cbDe6FU7cwDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFjAUBgNVBAgMDU1hc3NhY2h1c2V0dHMxDzANBgNVBAcMBkJvc3RvbjEPMA0GA1UECgwGS2V5dG9zMRkwFwYDVQQLDBBSb290IENlcnRpZmljYXRlMB4XDTI1MDYwNTAxNDExNFoXDTI2MDYwNTAxNDExNFowajELMAkGA1UEBhMCVVMxFjAUBgNVBAgMDU1hc3NhY2h1c2V0dHMxDzANBgNVBAcMBkJvc3RvbjEPMA0GA1UECgwGS2V5dG9zMSEwHwYDVQQLDBhJbnRlcm1lZGlhdGUgQ2VydGlmaWNhdGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCu8SP9tN+S+zbBWFVNgsDeBHJWOvkSeCCkgkgMNTTC8yj4vpPd+njSFte3lgeeACaDvb3WZOZLKQmTAjCSNdT8jNs6TRDCPrwsPDEl7b0r8R1WFje/Pesw+HkKvNZFTdoASvkM8EtrsLH26P1EAkXboXdvJGHUVNITcobKJRNgTNKT0Q3X4RAggCsBZu5KuSOsfEA2KgMGA9elzQCoHz1B/5QupW0MK8MIb3O7foL2BcricqtIVKh0NuqYsrGhPxJFKiu7OrrlUC0K4NmXXS67amLSabXUpKcIkSwWe30MoV3Awnomj3sC/sfwWio4yN3QA64j3Pai0IiEJ8irdy+LAgMBAAGjUDBOMB0GA1UdDgQWBBRKu2Yzi8JcgSuUAIttVnXLeZlrEDAfBgNVHSMEGDAWgBQb2JHADr4JlXuPG5K8QKkCLfPYsTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQDCgQVEEUd/kjp8zuJR6ZM7ngk+/GREhC+wYfRWbhR9YK+qPTrvwWOjl+9vTCSANZ/CHiPHkeH/m2zyzBFT4GDcgHMeXVi2bMdew6fiEU1KoeOkcRCodZxda9T1f+n+0nwQSkj3AogqwpZdnfmEDlw6Eqt5Ru+s8a00NytHtDQJpXQjQBcbWRSm1hGm38vAuebgTRgCh87qVMN3rdg0BigZXSjbp0JSCu/RXucQ7QGtvFG3bsRHP7S5o82XY/WVP2Swz4FwObhOc1W1DDclbCKzgX+mLkgoUr71dMYb15ndQO5SyvIBFluKpeIx1mRxcHx/rFW1gydQsXUGW7ffzx2m"))
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(getBytesFromBase64(t, "MIIDpTCCAo2gAwIBAgIUThAwm6dxtmbE41P86QA6JCDlhsUwDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFjAUBgNVBAgMDU1hc3NhY2h1c2V0dHMxDzANBgNVBAcMBkJvc3RvbjEPMA0GA1UECgwGS2V5dG9zMRkwFwYDVQQLDBBSb290IENlcnRpZmljYXRlMB4XDTI1MDYwNTAxNDExNFoXDTI2MDYwNTAxNDExNFowYjELMAkGA1UEBhMCVVMxFjAUBgNVBAgMDU1hc3NhY2h1c2V0dHMxDzANBgNVBAcMBkJvc3RvbjEPMA0GA1UECgwGS2V5dG9zMRkwFwYDVQQLDBBSb290IENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0CP9JmIl9VTWCcpX3a1Y3XO6OKsqDgXYD2HFcVG5axMwObvGarZ7S9x4G9GMIfuTsZh9mDIUFmzX9P/XGhVjG6vURBYnf/Fx5vVxAcnTKopD7xUdI3XATbu0hO3vEPwPyxMoWOR9pN4nrXD/wlZNH4ZNaPTpo2xjWU3Q7Akt5TESna73K5Wkg6JKDGwIvGbeUlPESX8xYCPx2etNgHgy2q4ps5010BDj6/V1UTlOIISkqfTnVdkM5iY9LKG0Klinf6iMguhDfvqW57skZtBgXZzeNOe57xqQqnGOaLUNi0kIT5mt3oIx9522aMdgMc5w5XNT/CiTp1Ff/YS/aqBD4wIDAQABo1MwUTAdBgNVHQ4EFgQUG9iRwA6+CZV7jxuSvECpAi3z2LEwHwYDVR0jBBgwFoAUG9iRwA6+CZV7jxuSvECpAi3z2LEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAOAQ/6aG0OOXpu9zvS4dqeZ4ZLsDTMJxPjqXH2opljcmhq6n59ROjUc3pt6feCfZTst6ImiB9NoTG8z+E3sN7MuK+MvmDsavrPxCOjq0Svw909EbaijfVwSFUIHJAIDa7ai2YZ1Wr7ZXEgt8ViK48iHghi6yTGdQuKGxwPnKlgOEXJhRFg2ex1dGbSanyK2CynqNtI4nmXGJb3rq+hEGOlCq89PKnps0TTVFejkQ/nUIVym9PH9s016ul7Hcn4M6xIdUhiMZ3lDUTnwf06Acr2/l/TALIIpGD340Hvjez/7DZBYZ9APqLPa+0C+q1tfc5wraDlfYejlO3Qr7497WWMQ=="))
	require.NoError(t, err)

	t.Run("no leaf", func(t *testing.T) {
		var url string
		c := sslAuthorityClient(&testshared.MockClient{
			DoJSONDecodeResponseFunc: func(req *http.Request, res any) error {
				url = req.URL.String()
				sr := res.(*signResponse)
				*sr = signResponse{
					Issuing: (*Certificate)(issuCert),
				}
				return nil
			},
		})
		certs, err := c.Sign(t.Context(), csr, nil)
		assert.ErrorContains(t, err, "ezca: unexpected error certificate was not returned after signing")
		assert.Equal(t, url, "https://test.ezca.io/api/CA/RequestSSLCertificateV2")
		assert.Empty(t, certs)
	})

	t.Run("no issuer", func(t *testing.T) {
		var url string
		c := sslAuthorityClient(&testshared.MockClient{
			DoJSONDecodeResponseFunc: func(req *http.Request, res any) error {
				url = req.URL.String()
				sr := res.(*signResponse)
				*sr = signResponse{
					NewCertificate: (*Certificate)(leafCert),
				}
				return nil
			},
		})
		certs, err := c.Sign(t.Context(), csr, nil)
		assert.ErrorContains(t, err, "ezca: unexpected error certificate issuer was not returned")
		assert.Equal(t, url, "https://test.ezca.io/api/CA/RequestSSLCertificateV2")
		assert.Empty(t, certs)
	})

	t.Run("two cert chain", func(t *testing.T) {
		var url string
		c := sslAuthorityClient(&testshared.MockClient{
			DoJSONDecodeResponseFunc: func(req *http.Request, res any) error {
				url = req.URL.String()
				sr := res.(*signResponse)
				*sr = signResponse{
					NewCertificate: (*Certificate)(leafCert),
					Issuing:        (*Certificate)(issuCert),
				}
				return nil
			},
		})
		certs, err := c.Sign(t.Context(), csr, nil)
		require.NoError(t, err)
		assert.Equal(t, certs, []*x509.Certificate{leafCert, issuCert})
		assert.Equal(t, url, "https://test.ezca.io/api/CA/RequestSSLCertificateV2")
	})

	t.Run("three cert chain", func(t *testing.T) {
		var url string
		c := sslAuthorityClient(&testshared.MockClient{
			DoJSONDecodeResponseFunc: func(req *http.Request, res any) error {
				r := signRequest{}
				d := json.NewDecoder(req.Body)
				err := d.Decode(&r)
				require.NoError(t, err)
				assert.Equal(t, r, signRequest{
					AuthorityID:        uuid.Nil,
					TemplateID:         uuid.Nil,
					CertificateRequest: rawCSR(csr),
					SubjectName:        "CN=test",
					ValidityInDays:     90,
					SelectedLocation:   "EZCA Go SDK",
					KeyUsages:          []KeyUsage{KeyUsageKeyEncipherment, KeyUsageDigitalSignature},
					ExtendedKeyUsages:  []ExtKeyUsage{ExtKeyUsageServerAuth, ExtKeyUsageClientAuth},
				})

				url = req.URL.String()
				sr := res.(*signResponse)
				*sr = signResponse{
					NewCertificate: (*Certificate)(leafCert),
					Issuing:        (*Certificate)(issuCert),
					Root:           (*Certificate)(rootCert),
				}
				return nil
			},
		})
		certs, err := c.Sign(t.Context(), csr, nil)
		require.NoError(t, err)
		assert.Equal(t, certs, []*x509.Certificate{leafCert, issuCert, rootCert})
		assert.Equal(t, url, "https://test.ezca.io/api/CA/RequestSSLCertificateV2")
	})
}

func TestRevoke(t *testing.T) {
	leafCert, err := x509.ParseCertificate(getBytesFromBase64(t, "MIIDrTCCApWgAwIBAgIUGPvTTixX6hCWbhl8h2VUvC1GNiQwDQYJKoZIhvcNAQELBQAwajELMAkGA1UEBhMCVVMxFjAUBgNVBAgMDU1hc3NhY2h1c2V0dHMxDzANBgNVBAcMBkJvc3RvbjEPMA0GA1UECgwGS2V5dG9zMSEwHwYDVQQLDBhJbnRlcm1lZGlhdGUgQ2VydGlmaWNhdGUwHhcNMjUwNjA1MDE0MTE0WhcNMjYwNjA1MDE0MTE0WjBiMQswCQYDVQQGEwJVUzEWMBQGA1UECAwNTWFzc2FjaHVzZXR0czEPMA0GA1UEBwwGQm9zdG9uMQ8wDQYDVQQKDAZLZXl0b3MxGTAXBgNVBAsMEExlYWYgQ2VydGlmaWNhdGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDK84U1UMIa/BwFwJ3tqyftAw0lBQX+K8pOvnunmDV1LweFLpArtO46fYQ8VhoE4z7BjIgaU/Spy5AJQ6wW5P7W17PBRO0Bj9HGmgEtI4o3S5jgmAgPMCi9x1BJRyYtnC3WENrrOKX65zEa37NGtdhUwQfDDK+fOUGpem9r/YQBj/ND0X92NG1XJ/zgAWrnKtKYDIUtLp+AmjKkEaMJHSudeu4j5ceC2qHi8qQQJXNSzMjd92zqcIVrZbQziWILfsqKiCBd87/cggB88ZTCA55+LOSaTpj5i7e81gTHwpe/Ul5YszsL5CpY2o3E7uVbBVCbOuGGAWX04fAXQDPRfxiXAgMBAAGjUzBRMB0GA1UdDgQWBBT1hDktlLs/V5y3b/GljpA293qF9DAfBgNVHSMEGDAWgBRKu2Yzi8JcgSuUAIttVnXLeZlrEDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAyF7i73r7j8844SgcYGAqpKbnJh0u34waWXnLWPb/4DVffKhgJccAUYAOUi6pzxtZg7pCWJKumk4K6RLmH69L1O/UBvVEfqOCoUZ3yz0bRVPUvYmlObbVyR9GddQifaGKxyZvpbfns1OcuOiNdOhgFV9khrkUodludQCxFvAQjrI02NiVHrMw53Z7qvEW61P7HvSAkQHSI80ANsIgiSmEoJoHYsHgkBnYrca7wuWTSaAno2VIgM6iB8+n3SXXOWsLKB7lnXM+Yjzi5oqxV4earsBxn9+NwSWrims9V52M0hMUaG20SMUyIqPb8KAmVdptYbHDzqj9A6kH1KU+bgRR5"))
	require.NoError(t, err)

	var url string
	c := sslAuthorityClient(&testshared.MockClient{
		DoResponseInAPIResultFunc: func(req *http.Request) (string, error) {
			url = req.URL.String()
			return "Successful", nil
		},
	})
	err = c.Revoke(t.Context(), leafCert)
	require.NoError(t, err)
	require.Equal(t, url, "https://test.ezca.io/api/CA/RevokeCertificateV2")
}

func TestRevokeWithThumbprint(t *testing.T) {
	var url string
	c := sslAuthorityClient(&testshared.MockClient{
		DoResponseInAPIResultFunc: func(req *http.Request) (string, error) {
			url = req.URL.String()
			return "Successful", nil
		},
	})
	err := c.RevokeWithThumbprint(t.Context(), [20]byte{0})
	require.NoError(t, err)
	require.Equal(t, url, "https://test.ezca.io/api/CA/RevokeCertificateV2")
}

func TestNewSSLAuthorityClient(t *testing.T) {
	bc, err := NewClient("test.ezca.io", &testshared.MockCredential{})
	require.NoError(t, err)

	t.Run("full", func(t *testing.T) {
		c, err := NewSSLAuthorityClient(bc, testSSLAuthority)
		require.NoError(t, err)
		assert.Equal(t, c, &SSLAuthorityClient{
			client: bc,
			ca:     testSSLAuthority,
		})
	})

	t.Run("missing client", func(t *testing.T) {
		c, err := NewSSLAuthorityClient(nil, testSSLAuthority)
		assert.ErrorContains(t, err, "cannot create an authority with a nil client")
		assert.Nil(t, c)
	})

	t.Run("missing ca", func(t *testing.T) {
		c, err := NewSSLAuthorityClient(bc, nil)
		assert.ErrorContains(t, err, "cannot create an authority with a nil authority")
		assert.Nil(t, c)
	})
}

func TestMarshalSANs(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		sans, err := marshalSANs([]string{}, []string{}, []net.IP{}, []*url.URL{})
		require.NoError(t, err)
		require.Empty(t, sans)
	})

	uri, err := url.Parse("https://test.ezca.io")
	require.NoError(t, err)

	for name, v := range map[string]*struct {
		dnsNames       []string
		emailAddresses []string
		ipAddresses    []net.IP
		uris           []*url.URL
		SANs           []*san
		err            string
	}{
		"all populated": {
			dnsNames:       []string{"test.ezca.io"},
			emailAddresses: []string{"alice@company.com"},
			ipAddresses:    []net.IP{net.ParseIP("127.0.0.1")},
			uris:           []*url.URL{uri},
			SANs: []*san{
				{
					NameType: nameTypeDNS,
					Value:    "test.ezca.io",
				},
				{
					NameType: nameTypeEmail,
					Value:    "alice@company.com",
				},
				{
					NameType: nameTypeIP,
					Value:    "127.0.0.1",
				},
				{
					NameType: nameTypeURI,
					Value:    "https://test.ezca.io",
				},
			},
		},
		"invalid dns": {
			dnsNames: []string{"bäd.ezca.io"},
			err:      "ezca: \"bäd.ezca.io\" cannot be encoded as an ASCII string",
		},
		"invalid email": {
			emailAddresses: []string{"bäd@email.com"},
			err:            "ezca: \"bäd@email.com\" cannot be encoded as an ASCII string",
		},
	} {
		t.Run(name, func(t *testing.T) {
			sans, err := marshalSANs(v.dnsNames, v.emailAddresses, v.ipAddresses, v.uris)
			if v.err == "" && len(v.SANs) > 0 {
				require.NoError(t, err)
				assert.Equal(t, sans, v.SANs)
			} else if v.err != "" {
				assert.ErrorContains(t, err, v.err)
				assert.Empty(t, sans)
			} else {
				t.Error("Invalid test setup")
			}
		})
	}
}

func TestIsASCII(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		require.NoError(t, isASCII("normal"))
	})

	t.Run("bad", func(t *testing.T) {
		require.ErrorContains(t, isASCII("nörmal"), "ezca: \"nörmal\" cannot be encoded as an ASCII string")
	})
}

func sslAuthorityClient(internalClient *testshared.MockClient) *SSLAuthorityClient {
	return &SSLAuthorityClient{
		client: &Client{
			internal:    internalClient,
			ezcaBaseURL: testURL,
		},
		ca: NewSSLAuthority(uuid.Nil, uuid.Nil),
	}
}

func getBytesFromBase64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	require.NoError(t, err)
	return b
}
