/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sm2

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"log"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestKey(t *testing.T) {
	req := require.New(t)

	priv, err := GenerateKey()
	req.NoError(err)

	der, err := MarshalSm2UnecryptedPrivateKey(priv)
	req.NoError(err)
	sk, err := ParsePKCS8UnecryptedPrivateKey(der)
	req.NoError(err)
	req.Equal(priv, sk)

	der, err = MarshalSm2PublicKey(&priv.PublicKey)
	req.NoError(err)
	pk, err := ParseSm2PublicKey(der)
	req.NoError(err)
	req.Equal(&priv.PublicKey, pk)
}

func TestSm2(t *testing.T) {
	req := require.New(t)

	priv, err := GenerateKey()
	req.NoError(err)
	req.Equal(true, priv.Curve.IsOnCurve(priv.X, priv.Y))
	fmt.Println("Check || private/public key on curve")
	pub := priv.Public().(*PublicKey)

	// test encrypt/decrypt
	msg := []byte("123456")
	d0, err := pub.Encrypt(msg)
	req.NoError(err)
	d1, err := priv.Decrypt(d0)
	req.NoError(err)
	req.Equal(msg, d1)
	fmt.Println("Check || encrypt/decrypt")

	// test pem
	ok, err := WritePrivateKeytoPem("priv.pem", priv, msg)
	req.NoError(err)
	req.Equal(true, ok)
	ok, err = WritePublicKeytoPem("pub.pem", pub, msg)
	req.NoError(err)
	req.Equal(true, ok)
	privKey, err := ReadPrivateKeyFromPem("priv.pem", msg)
	req.NoError(err)
	req.Equal(priv, privKey)
	pubKey, err := ReadPublicKeyFromPem("pub.pem", msg)
	req.NoError(err)
	req.Equal(pub, pubKey)
	fmt.Println("Check || pem")

	// test sign/verify
	msg = []byte("test data to be signed")
	signdata, err := privKey.Sign(rand.Reader, msg, nil)
	req.NoError(err)
	req.Equal(true, privKey.Verify(msg, signdata))
	req.Equal(true, pubKey.Verify(msg, signdata))
	fmt.Println("Check || sign/verify")
}

func TestCert(t *testing.T) {
	req := require.New(t)

	priv, err := GenerateKey()
	req.NoError(err)

	templateReq := CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test"},
		},
		SignatureAlgorithm: SM2WithSM3,
	}
	_, err = CreateCertificateRequestToPem("req.pem", &templateReq, priv)
	req.NoError(err)
	pkcs10, err := ReadCertificateRequestFromPem("req.pem")
	req.NoError(err)
	req.NoError(pkcs10.CheckSignature())
	fmt.Println("Check || PKCS10 signature")

	testExtKeyUsage := []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")
	commonName := "test.example.com"
	template := Certificate{
		// SerialNumber is negative to ensure that negative
		// values are parsed. This is due to the prevalence of
		// buggy code that produces certificates with negative
		// serial numbers.
		SerialNumber: big.NewInt(-1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"TEST"},
			Country:      []string{"China"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Gopher",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "NL",
				},
			},
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Unix(100000, 0),

		SignatureAlgorithm: SM2WithSM3,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     KeyUsageCertSign,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA: true,

		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

		DNSNames:       []string{"test.example.com"},
		EmailAddresses: []string{"gopher@golang.org"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

		PolicyIdentifiers:   []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		PermittedDNSDomains: []string{".example.com", "example.com"},

		CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

		ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: extraExtensionData,
			},
			// This extension should override the SubjectKeyId, above.
			{
				Id:       oidExtensionSubjectKeyId,
				Critical: false,
				Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
			},
		},
	}
	ok, err := CreateCertificateToPem("cert.pem", &template, &template, priv.Public().(*PublicKey), priv)
	req.NoError(err)
	req.Equal(ok, true)
	cert, err := ReadCertificateFromPem("cert.pem")
	req.NoError(err)
	req.NoError(cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature))
	fmt.Println("Check || X.509 signature")
}

func BenchmarkSM2(t *testing.B) {
	t.ReportAllocs()
	msg := []byte("test")
	priv, err := GenerateKey() // 生成密钥对
	if err != nil {
		log.Fatal(err)
	}
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sign, err := priv.Sign(rand.Reader, msg, nil) // 签名
		if err != nil {
			log.Fatal(err)
		}
		priv.Verify(msg, sign) // 密钥验证
		// if ok != true {
		// 	fmt.Printf("Verify error\n")
		// } else {
		// 	fmt.Printf("Verify ok\n")
		// }
	}
}
