// Copyright © 2025 bddjr
// MIT license

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"syscall/js"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

const (
	certPEMType = "CERTIFICATE"
	keyPEMType  = "PRIVATE KEY"
)

func main() {
	println("Hello WebAssembly")
	js.Global().Set("backend", js.ValueOf(map[string]any{
		"GenerateCACert":     funcof(generateCACert),
		"GenerateServerCert": funcof(generateServerCert),
	}))
	js.Global().Get("divloading").Call("removeAttribute", "loading")
	select {}
}

func funcof(f func(input string) (map[string]any, error)) js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		var output map[string]any
		var outErr error
		func() {
			defer func() {
				if err := recover(); err != nil {
					buf := make([]byte, 64<<10)
					buf = buf[:runtime.Stack(buf, false)]
					outErr = fmt.Errorf("golang panic: %v\n%s", err, buf)
				}
			}()
			output, outErr = f(args[0].String())
		}()
		if outErr != nil {
			return js.ValueOf(map[string]any{
				"Success": false,
				"Error":   outErr.Error(),
			})
		}
		return js.ValueOf(output)
	})
}

func toUint8Array(src []byte) js.Value {
	dst := js.Global().Get("Uint8Array").New(len(src))
	js.CopyBytesToJS(dst, src)
	return dst
}

// 生成 ECC 私钥
func generateKey(name string) (*ecdsa.PrivateKey, error) {
	var p elliptic.Curve
	switch name {
	case "P-224":
		p = elliptic.P224()
	case "P-256":
		p = elliptic.P256()
	case "P-384":
		p = elliptic.P384()
	case "P-521":
		// 浏览器不支持这个算法，因此前端没有这个选项。
		p = elliptic.P521()
	default:
		return nil, errors.New("generateKey: unknown name")
	}
	return ecdsa.GenerateKey(p, rand.Reader)
}

// 编码证书为 PEM 格式
func certToPEM(DER []byte) string {
	PEM := pem.EncodeToMemory(&pem.Block{
		Type:  certPEMType,
		Bytes: DER,
	})
	return string(PEM)
}

// 编码 PKCS#8 私钥为 PEM 格式
func pkcs8ToPEM(PKCS8 []byte) string {
	PEM := pem.EncodeToMemory(&pem.Block{
		Type:  keyPEMType,
		Bytes: PKCS8,
	})
	return string(PEM)
}

// Copy from "crypto/tls".
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("parsePrivateKey: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("parsePrivateKey: failed to parse private key")
}

func generateCACert(input string) (map[string]any, error) {
	requestBody := &struct {
		CN   string
		Days int64
		ECC  string
	}{}

	err := json.Unmarshal([]byte(input), requestBody)
	if err != nil {
		return nil, err
	}

	// 生成私钥
	privateKey, err := generateKey(requestBody.ECC)
	if err != nil {
		return nil, err
	}

	// 编码私钥为 PKCS8 格式
	privPKCS8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	// 创建证书模板
	Time := time.Now()
	days := time.Duration(requestBody.Days) * (time.Hour * 24)
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: requestBody.CN,
		},
		NotBefore: Time,
		NotAfter:  Time.Add(days),
		// KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// 生成自签名 CA 证书
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		return nil, err
	}

	// 响应
	return map[string]any{
		"Success": true,
		"Error":   "",
		"Cert":    certToPEM(certDER),    // PEM
		"Key":     pkcs8ToPEM(privPKCS8), // PEM
		"Time":    Time.UnixMilli(),      // UnixMilli
	}, nil
}

func generateServerCert(input string) (map[string]any, error) {
	requestBody := &struct {
		CA struct {
			Cert string
			Key  string
		}
		CN   string
		Days int64
		ECC  string
		SAN  struct {
			DNS []string
			IP  []string
		}
		P12Key string
	}{}

	err := json.Unmarshal([]byte(input), requestBody)
	if err != nil {
		return nil, err
	}

	// 解析 CA 证书
	var CACert *x509.Certificate
	if strings.HasPrefix(requestBody.CA.Cert, "-----") {
		// PEM
		DERBlock, _ := pem.Decode([]byte(requestBody.CA.Cert))
		if DERBlock == nil || DERBlock.Type != certPEMType {
			return nil, errors.New("Failed to decode PEM CERTIFICATE")
		}
		CACert, err = x509.ParseCertificate(DERBlock.Bytes)
	} else {
		// DER
		CACert, err = x509.ParseCertificate([]byte(requestBody.CA.Cert))
	}
	if err != nil {
		return nil, err
	}

	// 解析 CA 私钥
	var CAKey any
	if strings.HasPrefix(requestBody.CA.Cert, "-----") {
		// PEM
		DERBlock, _ := pem.Decode([]byte(requestBody.CA.Key))
		if DERBlock == nil || DERBlock.Type != keyPEMType {
			return nil, errors.New("Failed to decode PEM PRIVATE KEY")
		}
		CAKey, err = parsePrivateKey(DERBlock.Bytes)
	} else {
		// DER
		CAKey, err = parsePrivateKey([]byte(requestBody.CA.Key))
	}
	if err != nil {
		return nil, err
	}

	// 生成私钥
	privateKey, err := generateKey(requestBody.ECC)
	if err != nil {
		return nil, err
	}

	// 编码私钥为 PKCS8 格式
	privPKCS8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	// 创建证书模板
	Time := time.Now()
	days := time.Duration(requestBody.Days) * (time.Hour * 24)
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: requestBody.CN,
		},
		NotBefore:             Time,
		NotAfter:              Time.Add(days),
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              requestBody.SAN.DNS,
		IPAddresses:           make([]net.IP, len(requestBody.SAN.IP)),
	}
	for i, v := range requestBody.SAN.IP {
		ip := net.ParseIP(v)
		if ip == nil {
			return nil, errors.New(fmt.Sprint("Error: SAN line ", i+1, " is invalid!"))
		}
		template.IPAddresses[i] = ip
	}

	// 生成自签名 Server 证书
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		CACert,
		&privateKey.PublicKey,
		CAKey,
	)
	if err != nil {
		return nil, err
	}

	// 解析新证书
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	// 编码为 PKCS12 格式
	p12, err := pkcs12.Legacy.Encode(
		privateKey,
		cert,
		nil,
		requestBody.P12Key,
	)
	if err != nil {
		return nil, err
	}

	// 构建响应
	return map[string]any{
		"Success": true,
		"Error":   "",
		"Cert":    certToPEM(certDER),    // PEM
		"Key":     pkcs8ToPEM(privPKCS8), // PEM
		"P12":     toUint8Array(p12),     // Uint8Array
		"Time":    Time.UnixMilli(),      // UnixMilli
	}, nil
}
