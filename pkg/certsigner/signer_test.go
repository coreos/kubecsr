package certsigner

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
	"time"

	capi "k8s.io/api/certificates/v1beta1"
)

var (
	caCrtFile        = "ca.crt"
	caKeyFile        = "ca.key"
	caMetricsCrtFile = "metric-ca.crt"
	caMetricsKeyFile = "metric-ca.key"

	csrBytes = []byte(`-----BEGIN CERTIFICATE REQUEST-----
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

	csrMetricsBytes = []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIIEpjCCAo4CAQAwYTELMAkGA1UEBhMCWFgxFTATBgNVBAcMDERlZmF1bHQgQ2l0
eTEcMBoGA1UECgwTc3lzdGVtOmV0Y2QtbWV0cmljczEdMBsGA1UEAwwUc3lzdGVt
OmV0Y2QtbWV0cmljOjEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDJ
kSE7th+Tu26k1me4guVF96CD7xA1xs9ujR7+/KMGKPYq+oPFZKOMX5xJziY4uF29
Nhp3VTTKVgU8QOT6Y0yaG4yjp6BPCSXY0/HEVPe2Z87xdPDGU2vrB5oeHVFRXDZ1
vDpODQ0M+F97aLqpQKXtthBjGaEmJH/DB4BqSGOH+5fDTggCWa0NfiscLNX99Tkf
jb1+fC/7bDpz3i/0op34pvS+hv1U9vFLlZpz7imka42lh6xutnOvUItTsngzZ2c+
54oUmb1Vyji1NG7rGZWsHtjPYXgvHq85hQwqlbVFYt169pfcDQGYwy+NSh847AN8
ORa2OQt4V9B8ZTTDdn4CQ93nTMTwKKf2dwcTxj84ABl4eYFWPIw6xOsPEOCtgNsw
2GpD5csh7hdsjI0WOw81fUfA9xbtc7SvP5vinCzIt2RE3sFuKXQPmlVLrtG5nQQg
aH/HXFXxYKrJhFTiDyGay1pat1UhDbmio8CCcSgSgb8O/M9ZSVVh0fEHOr2e38vo
K1p0VgHZ3ITL4/a/3Ex70sA/PWzYvrGb/FOhP1CRLx0CstQjVgp4dQqPlZJWy3qy
iyZgR5xCgx9nElRKh2ntJmyv9msMmYQUgNmt2uPHoOAaYAj49lz5VtttwXv23YwX
20ODXe3d6pwDeCGbBj2Atkp2Jvc5z4aG/ZqyeQUVjwIDAQABoAAwDQYJKoZIhvcN
AQELBQADggIBAAlddAVwfZeZqJQwd/0WsLq0mH3TcevKkRAy/mUP/Jna+ug8I+xw
DjWjKXv0EyXif3IFP7mzrmaW1ksqcOwoUBGMMc17kcXVRP9VGWM0YmXYU2TrjIkg
YQTVdQXP5+W7VwHL6m/rdsOt/zy1OFVAn88f5hrNEnkmv7MwwK+BgWMdRT3lTWbi
HQF86vjW/0joR+L0vGBJxlGJma+c6wxxsPPi0eRDJuThV9Yzr0VhXLiLlimm1e2N
dT9JL2n/RAtb6LbJfqqFWvpr64ZnPz/s+bhMnd+Ufk5cVMqov4jvZijZQlhqR8R/
qSaopgZfFdQuL2uZLTHrDNTZfLIXiu7qIyRvlpCPJgyJ29LVBzxPurg1euhln/pr
G94cfrZe/dMEQvEQrSSyUcxOXzeYm3+uT+xIp7yK5z5V8w7qmR+PUqRIKOZ6TBSU
YxCa7IieBKN82wm9X2FulifD1LVUvHaztGnhipV2UmLo0Wrwo78jHJz0nw0bYEMd
Ba+1yisQjcSz21Zsl7lbm2MKfrR8cx5AoP2Xn75jGe9L+n6YEx2MEHZp7/s7X1hf
Ax2vGHbg+P6Yof8alxqe2AHzAtlbUSmwXsf8efs/3Uey07x55fC7O42hj5VNLbfV
qqOj7/EZleCtQplqyOwF8Mt6h4LZBE4lgB27HNtX5VAcZsUnVTtJrO0e
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

	caMetricsCrtBytes = []byte(`-----BEGIN CERTIFICATE-----
MIIFXTCCA0WgAwIBAgIURQbfHSBCKeD2UL952fkS5lgYJowwDQYJKoZIhvcNAQEL
BQAwPjELMAkGA1UEBhMCWFgxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTEYMBYGA1UE
CgwPZmFrZS1tZXRyaWNzLWNhMB4XDTE5MDMyMDExNTMyM1oXDTE5MDQxOTExNTMy
M1owPjELMAkGA1UEBhMCWFgxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTEYMBYGA1UE
CgwPZmFrZS1tZXRyaWNzLWNhMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
AgEAyZEhO7Yfk7tupNZnuILlRfegg+8QNcbPbo0e/vyjBij2KvqDxWSjjF+cSc4m
OLhdvTYad1U0ylYFPEDk+mNMmhuMo6egTwkl2NPxxFT3tmfO8XTwxlNr6weaHh1R
UVw2dbw6Tg0NDPhfe2i6qUCl7bYQYxmhJiR/wweAakhjh/uXw04IAlmtDX4rHCzV
/fU5H429fnwv+2w6c94v9KKd+Kb0vob9VPbxS5Wac+4ppGuNpYesbrZzr1CLU7J4
M2dnPueKFJm9Vco4tTRu6xmVrB7Yz2F4Lx6vOYUMKpW1RWLdevaX3A0BmMMvjUof
OOwDfDkWtjkLeFfQfGU0w3Z+AkPd50zE8Cin9ncHE8Y/OAAZeHmBVjyMOsTrDxDg
rYDbMNhqQ+XLIe4XbIyNFjsPNX1HwPcW7XO0rz+b4pwsyLdkRN7Bbil0D5pVS67R
uZ0EIGh/x1xV8WCqyYRU4g8hmstaWrdVIQ25oqPAgnEoEoG/DvzPWUlVYdHxBzq9
nt/L6CtadFYB2dyEy+P2v9xMe9LAPz1s2L6xm/xToT9QkS8dArLUI1YKeHUKj5WS
Vst6sosmYEecQoMfZxJUSodp7SZsr/ZrDJmEFIDZrdrjx6DgGmAI+PZc+VbbbcF7
9t2MF9tDg13t3eqcA3ghmwY9gLZKdib3Oc+Ghv2asnkFFY8CAwEAAaNTMFEwHQYD
VR0OBBYEFBB/Exg1rCBHZOZJK24YrRKi7ArnMB8GA1UdIwQYMBaAFBB/Exg1rCBH
ZOZJK24YrRKi7ArnMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIB
AJqp6IpzHjuM5Pnfv3L9HFbVYp/q4XrvUKw9vUXD4mADL8XQVYCOLi9Zixfz1Ke9
Gmk7sUZXlcAAQH80DecqB71XT0tuGobSrUOVVVM0qZsTt8pedDfQTwHqz+wl8MNE
Pd/Rte4VgwHQjaTYX6CnmqmnTvZVHwj5myi00xpU3sFxHk1brUEnEe7nyuR4dJ8k
DR/qtB9alR/mJwse0bWQI4lo9QakEoA5PLFSvUnXxNqOiQR3tRAxist6Td6g1Upe
/se6yv+1IRAuZXoSJpwmoRnxSLVZtD6EGLZK35hRjfvZx+G2422rst56thzVC4VS
yFrH5lgT66cyn3rw8cgqwufb5pspB4Qsc05Y0Ky1PQBst2rvhWiJaMJNma2+R/3/
EMyCIbsp2niXwPLkqSOCKhpbOBlPYlfvEY2PivI9CF2FnFv7vyhqk6n7L79puKJk
/1VriB6uUVG8HdAzEazXULYSOPsgZ7kwr+8hI6jkrMPsisjIPMbdvD/pkyEh9iu7
4lfBjgE382fdY2ShbHVdjq6dbPmH3Ds7/RaQQP8esZs29ll9Y7irr63RZkY3OiR0
/aYkCM2BLtayR9wuunBEFGPwAZLIQKHk5MJSLsix9l0uV+N897agsKQ87Luxn1vw
Rd1ImiuaAD0Dz9rSJQyZrzFGvZRCqTUC9c5Vp1/X8djW
-----END CERTIFICATE-----`)

	caKeyBytes = []byte(`-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`)

	caMetricsKeyBytes = []byte(`-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`)
)

func loadAllCrts(t *testing.T) {
	loadCrt(caKeyBytes, caKeyFile, t)
	loadCrt(caCrtBytes, caCrtFile, t)
	loadCrt(caMetricsKeyBytes, caMetricsKeyFile, t)
	loadCrt(caMetricsCrtBytes, caMetricsCrtFile, t)
}

func loadCrt(data []byte, filename string, t *testing.T) {
	if err := ioutil.WriteFile(filename, data, 0644); err != nil {
		t.Fatalf("error writing credentials to file: %v", err)
	}
}

func TestNewSignerCA(t *testing.T) {
	type TestData struct {
		SignerCAFiles
		csrFileBytes []byte
		want         string
	}

	for _, test := range []TestData{
		{
			SignerCAFiles{caCrtFile, caKeyFile, "", ""},
			csrBytes,
			"ok",
		},
		{
			SignerCAFiles{caCrtFile, caKeyFile, "", ""},
			csrMetricsBytes,
			"error",
		},
		{
			SignerCAFiles{caCrtFile, caKeyFile, caMetricsCrtFile, caMetricsKeyFile},
			csrMetricsBytes,
			"ok",
		},
		{
			SignerCAFiles{caCrtFile, caKeyFile, caMetricsCrtFile, caMetricsKeyFile},
			csrBytes,
			"ok",
		},
		{
			SignerCAFiles{"", "", caMetricsCrtFile, caMetricsKeyFile},
			csrBytes,
			"error",
		},
		{
			SignerCAFiles{"", "", caMetricsCrtFile, caMetricsKeyFile},
			csrMetricsBytes,
			"ok",
		},
	} {

		loadAllCrts(t)
		caFiles := test.SignerCAFiles
		csr := createCSR(test.csrFileBytes)
		profile, _ := getProfile(csr)
		_, err := newSignerCA(&caFiles, csr)
		got := gotError(err)
		if test.want != got {
			t.Errorf("NewSignerCA profile %s want (%s) got (%s) error: %v", profile, test.want, got, err)
		}
		if err := cleanUp(caFiles); err != nil {
			t.Fatalf("NewSignerCA error deleting files %v", err)
		}
	}
}

func TestSign(t *testing.T) {
	type TestData struct {
		SignerCAFiles
		csrFileBytes []byte
		caCrt        []byte
		dnsName      string
		want         string
	}

	for _, test := range []TestData{
		{
			SignerCAFiles{caCrtFile, caKeyFile, "", ""},
			csrBytes,
			caCrtBytes,
			"system:etcd-peer:1",
			"ok",
		},
		{
			SignerCAFiles{caCrtFile, caKeyFile, caMetricsCrtFile, caMetricsKeyFile},
			csrMetricsBytes,
			caMetricsCrtBytes,
			"system:etcd-metric:1",
			"ok",
		},
		{
			SignerCAFiles{caCrtFile, caKeyFile, caMetricsCrtFile, caMetricsKeyFile},
			csrMetricsBytes,
			caMetricsCrtBytes,
			"google.com",
			"error",
		},
	} {

		loadAllCrts(t)

		caFiles := test.SignerCAFiles
		config := Config{
			SignerCAFiles:          caFiles,
			ListenAddress:          "0.0.0.0:6443",
			EtcdMetricCertDuration: 1 * time.Hour,
			EtcdPeerCertDuration:   1 * time.Hour,
			EtcdServerCertDuration: 1 * time.Hour,
		}

		csr := createCSR(test.csrFileBytes)
		policy := signerPolicy(config)
		signerCA, err := newSignerCA(&caFiles, csr)
		if err != nil {
			t.Errorf("error setting up signerCA:%v", err)
		}
		s, err := NewSigner(signerCA, &policy)
		if err != nil {
			t.Errorf("error setting up signer:%v", err)
		}

		signedCSR, errMsg := s.Sign(csr)
		if errMsg != nil {
			t.Errorf("error signing csr: %v", errMsg)
		}
		if len(signedCSR.Status.Certificate) == 0 {
			t.Errorf("csr not signed: %v", err)
		}

		roots := x509.NewCertPool()
		ok := roots.AppendCertsFromPEM(test.caCrt)
		if !ok {
			t.Errorf("failed to parse root certificate")
		}
		block, _ := pem.Decode([]byte(signedCSR.Status.Certificate))
		if block == nil {
			t.Errorf("failed to parse certificate PEM")
		}

		opts := x509.VerifyOptions{
			DNSName: test.dnsName,
			Roots:   roots,
		}
		cert, _ := x509.ParseCertificate(block.Bytes)
		_, verr := cert.Verify(opts)
		got := gotError(verr)
		if got != test.want {
			t.Errorf("TestSign want %s got %s err %v", test.want, got, verr)
		}
		// cleanup
		if err := cleanUp(caFiles); err != nil {
			t.Fatalf("error deleting files %v", err)
		}
	}
}

func createCSR(csr []byte) *capi.CertificateSigningRequest {
	return &capi.CertificateSigningRequest{
		Spec: capi.CertificateSigningRequestSpec{
			Request: csr,
			Usages: []capi.KeyUsage{
				capi.UsageSigning,
				capi.UsageKeyEncipherment,
				capi.UsageServerAuth,
				capi.UsageClientAuth,
			},
		},
	}
}

func cleanUp(files SignerCAFiles) error {
	f := reflect.ValueOf(files)
	for i := 0; i < f.NumField(); i++ {
		file := fmt.Sprintf("%s", f.Field(i).Interface())
		if file == "" {
			continue
		}
		if err := os.Remove(file); err != nil {
			return err
		}
	}
	return nil
}

func gotError(err error) string {
	switch t := err.(type) {
	case nil:
		return "ok"
	case error:
		return "error"
	default:
		return fmt.Sprintf("invalid type: %v", t)
	}
}
