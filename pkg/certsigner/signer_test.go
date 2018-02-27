package certsigner

import (
	"io/ioutil"
	"os"
	"testing"

	capi "k8s.io/api/certificates/v1beta1"
)

var (
	caCrtFile = "ca.crt"
	caKeyFile = "ca.key"
	csrBytes  = []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIICojCCAYoCAQAwXTELMAkGA1UEBhMCWFgxFTATBgNVBAcMDERlZmF1bHQgQ2l0
eTEaMBgGA1UECgwRc3lzdGVtOmV0Y2QtcGVlcnMxGzAZBgNVBAMMEnN5c3RlbTpl
dGNkLXBlZXI6MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANALpBiW
8vVBDwgRGuj0FqOk85trY9YHJUsGlRCthnvKfWt7WGTwEWpui8yk1N0i1YY0aHtA
Q450aeg+cBx7Ptmubyt+vvS1swTuKe7cRKj7Nws8ukMT2EK6Ju3es5zeiomWU67k
q4U0D2XQenVVP5flr/c/KW58AfRL0+XOzQxrLao5Sm9Yp2o3/bcpZv7LN95tigO3
/yXxqoGp/9q9UCvRxaaPHjKryh6ZcuG9Acar5HGen8pcr1jiNwvRt6CtKd8hFgGh
uWU481VGuXvCwKgNv8R8RelvdCJtxpqaZu8t6TpY2im64WJx/Q+oVJIKYqQ1I1Zy
aAgiQUhSAyTjFvECAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQCv9pasM29bp06+
48oc8UMwjVz5DqlIGi4NyJ6DqUpKJr+C68sMnxqKqinGNTI3XedPHv5weKRckFRk
MPVwDE1P3IxkmghoVtUJ9hM0AwRXaGD8pHWXq3JiryxoIGXCz2p0oEGczKmkxBki
0sBVniocg2njSzIJeBag9kZwskhwfralaEkOpxs7iNBHmBDg3IdSCZqO+ikVg0b/
X6IGYVFVglScoQS4xQGiyhxzZhgAjKFsRaAWjcpU6LkSpF9org3KpZtcKeV/ZwZT
5KuRy6rsTWvlX/8onttDqtsipBkyVKlBsrsnfO3A0XwhEt79h9fnxMK94K0quTVA
jvINeymP
-----END CERTIFICATE REQUEST-----`)

	caCrtBytes = []byte(`-----BEGIN CERTIFICATE-----
MIIFDTCCAvWgAwIBAgIJAMPkKOVfXGKZMA0GCSqGSIb3DQEBCwUAMBIxEDAOBgNV
BAMMB2Zha2UtY2EwHhcNMTgwMjIyMTg1MTA3WhcNMjgwMjIwMTg1MTA3WjASMRAw
DgYDVQQDDAdmYWtlLWNhMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
pOcWmKHVuJIy1mTWG4/PfDj1zL7YHpg2SQ4uIL2mUyGVT5sqRkz1fPsDQKzm4iYs
pMad7rd/0hseNTENt+ZbmLUovnFeqQ/U5OGXnpzarLZexQEcbpw5xHoahQAFKrAC
arBOMXhShF828OqdbSiL9w9BTMs9dcLzu53AsA3dC6qDsW7mud2Bz9ais/GyIL7P
7ZWXZwCisixbAc88CAivECyfSvhiELFeh2wC2k/fH7aG//gH95gSyrV7Ai1n/1tF
TE+SW7LvLSJVUBfUPIlS2UGsO+/yQGnQHmA2WvssTsNIoMOqJ5xM3T0ZRSPC39hL
9F5ubCMmcfCj55DeAFGJa0/s3YSO0Y/XFWqqf5pAGNhkTTK6ZYCpqNOcDaRqkYUt
YTuMBRHD7mW1kmxko6L2nlfp2cvRiMEFCrATZB2haHWPj2ly0E+oRpCp1Pr+Zou6
37YFhpCmxI1PnfypWrFbjzG4U3AU+9+qjLvDwbA8YO5O+AybbtA3lvdUHWPnJWvV
v9Xtl7UXg6PjGmOHEDF+lVBvvfTbaXLqYmt8RGJbaxvZD9RYnLBswl/13tf93FuC
E+XJNabuS9PA42Cu3xx7FM582uM60uiEbk7DEsJs93NWrlAO1Sefmcw0KL3oHvCU
hK4x04OiqOpx6EOkJ58yfc45U1sPnWos5wy7HKTAxTkCAwEAAaNmMGQwHQYDVR0O
BBYEFE24MCpdZZHhv4hRu49eNKdjI/INMB8GA1UdIwQYMBaAFE24MCpdZZHhv4hR
u49eNKdjI/INMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMA0G
CSqGSIb3DQEBCwUAA4ICAQAoWfLQ6gKZFLRz4pyWcbP6ukBafwmwhdA2YCdlT/ay
jUetwFhgiFE3xiymfiGwD2TsB+vmg7NIu0zMhCotnpBclIz6TU3ll4IuryuJYkgW
Nfj9f1P6q1feJl2QGutfWFO566FVGikD09X/99Wm+vqIusrJA10hbUFEB/G188pz
AKjeKt0VjRCKQwvNLAWcqyQRXAq7mqwkCDSOdL0sFyNaSGVJsfde7wtuQ4NKVKhi
5v7fpTvYkJrtr6KnTjG5CgwwBSC6Hu1+kA97NMlGEidkprjNrA6L8Qiloy1cOWM6
oD7Fan+KgbeMcFSB6H1v0xiqUQShWhLgL22+HngAoneM+t+tq9QfAsw4l3GZrdjX
XQ9SWwCr66rrOBJiQl+e1/t7B2r8dO7Zypuy5uR28nXX7BNiDP58wWQqeux6aLz2
qlPD15R+FkgmNXqjPAhwou7Eaigy1KbKhhdqj2EMkQZhe+RWNDP6gKXFLmj5vbEL
E/Mb0p/otozmx7Y7QIkXSh//H/x8Bi/vLRtNQmbgCYu6iNNOKRTiVtaYRcy7vj4Z
iE6rkr//NhxuZeaBDItIRC4uRcSF8noeFkGuQGb22vf8HnwDKnNF9Ty6Zg8CfRVv
Rt0zd4OjeRzVNivCQ3ilpj5uv2vob9+9svKVatdFYst93eaBvWGd1hbsev7T/3t3
bA==
-----END CERTIFICATE-----`)

	caKeyBytes = []byte(`-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`)
)

func loadAllCrts(t *testing.T) {
	loadCrt(caKeyBytes, caKeyFile, t)
	loadCrt(caCrtBytes, caCrtFile, t)
}

func loadCrt(data []byte, filename string, t *testing.T) {
	if err := ioutil.WriteFile(filename, data, 0644); err != nil {
		t.Fatalf("error writing credentials to file: %v", err)
	}
}

func TestSign(t *testing.T) {
	loadAllCrts(t)
	config := Config{
		CACertFile:             caCrtFile,
		CAKeyFile:              caKeyFile,
		ListenAddress:          "0.0.0.0:6443",
		EtcdPeerCertDuration:   100,
		EtcdServerCertDuration: 100,
	}

	s, err := NewSigner(config)
	if err != nil {
		t.Errorf("error setting up signer:%v", err)
	}

	csr := &capi.CertificateSigningRequest{
		Spec: capi.CertificateSigningRequestSpec{
			Request: csrBytes,
			Usages: []capi.KeyUsage{
				capi.UsageSigning,
				capi.UsageKeyEncipherment,
				capi.UsageServerAuth,
				capi.UsageClientAuth,
			},
		},
	}

	signedCSR, errMsg := s.Sign(csr)
	if errMsg != nil {
		t.Errorf("error signing csr: %v", errMsg)
	}

	if len(signedCSR.Status.Certificate) == 0 {
		t.Errorf("csr not signed: %v", err)

	}

	if err := os.Remove(caCrtFile); err != nil {
		t.Errorf("error deleting file %s: %v", caCrtFile, err)
	}

	if err := os.Remove(caKeyFile); err != nil {
		t.Errorf("error deleting file %s: %v", caKeyFile, err)
	}
}
