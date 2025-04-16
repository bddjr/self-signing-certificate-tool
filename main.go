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
	"embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

//go:embed frontend/*
var FS embed.FS

const (
	certPEMType = "CERTIFICATE"
	keyPEMType  = "PRIVATE KEY"
)

func main() {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}

	openBrowser(l.Addr().String())

	err = http.Serve(l, getRouter())
	if err != http.ErrServerClosed {
		panic(err)
	}
}

func openBrowser(addr string) {
	url := "http://" + addr
	print("\n  Self-Signing Certificate Tool\n  " + url + "\n\n")
	switch runtime.GOOS {
	case "windows":
		exec.Command("cmd", "/c", "start", url).Start()
	case "darwin":
		exec.Command("open", url).Start()
	default:
		exec.Command("xdg-open", url).Start()
	}
}

func getRouter() http.Handler {
	router := http.NewServeMux()

	router.HandleFunc("/api/generateCACert", mustPOST(generateCACert))
	router.HandleFunc("/api/generateServerCert", mustPOST(generateServerCert))

	f, _ := fs.Sub(FS, "frontend")
	router.Handle("/", http.FileServerFS(f))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		router.ServeHTTP(w, r)
	})
}

func mustPOST(f func(w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		f(w, r)
	}
}

func write200JSON(w http.ResponseWriter, responseBody any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(responseBody)
}

func write400Error(w http.ResponseWriter, err error) {
	w.WriteHeader(400)
	io.WriteString(w, err.Error())
}

func write500Error(w http.ResponseWriter, err error) {
	w.WriteHeader(400)
	io.WriteString(w, err.Error())
}

func write400String(w http.ResponseWriter, err string) {
	w.WriteHeader(400)
	io.WriteString(w, err)
}

func write500String(w http.ResponseWriter, err string) {
	w.WriteHeader(400)
	io.WriteString(w, err)
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

func generateCACert(w http.ResponseWriter, r *http.Request) {
	requestBody := &struct {
		CN   string
		Days int64
		ECC  string
	}{}

	err := json.NewDecoder(r.Body).Decode(requestBody)
	if err != nil {
		write500Error(w, err)
		return
	}

	// 生成私钥
	privateKey, err := generateKey(requestBody.ECC)
	if err != nil {
		write500Error(w, err)
		return
	}

	// 编码私钥为 PKCS8 格式
	privPKCS8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		write500Error(w, err)
		return
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
		write500Error(w, err)
		return
	}

	// 构建响应
	responseBody := &struct {
		Cert string // PEM
		Key  string // PEM
		Time int64  // UnixMilli
	}{
		Cert: certToPEM(certDER),
		Key:  pkcs8ToPEM(privPKCS8),
		Time: Time.UnixMilli(),
	}
	write200JSON(w, responseBody)
}

func generateServerCert(w http.ResponseWriter, r *http.Request) {
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

	err := json.NewDecoder(r.Body).Decode(requestBody)
	if err != nil {
		write500Error(w, err)
		return
	}

	// 解析 CA 证书
	var CACert *x509.Certificate
	if strings.HasPrefix(requestBody.CA.Cert, "-----") {
		// PEM
		DERBlock, _ := pem.Decode([]byte(requestBody.CA.Cert))
		if DERBlock == nil || DERBlock.Type != certPEMType {
			write500String(w, "Failed to decode PEM CERTIFICATE")
			return
		}
		CACert, err = x509.ParseCertificate(DERBlock.Bytes)
	} else {
		// DER
		CACert, err = x509.ParseCertificate([]byte(requestBody.CA.Cert))
	}
	if err != nil {
		write500Error(w, err)
		return
	}

	// 解析 CA 私钥
	var CAKey any
	if strings.HasPrefix(requestBody.CA.Cert, "-----") {
		// PEM
		DERBlock, _ := pem.Decode([]byte(requestBody.CA.Key))
		if DERBlock == nil || DERBlock.Type != keyPEMType {
			write500String(w, "Failed to decode PEM PRIVATE KEY")
			return
		}
		CAKey, err = parsePrivateKey(DERBlock.Bytes)
	} else {
		// DER
		CAKey, err = parsePrivateKey([]byte(requestBody.CA.Key))
	}
	if err != nil {
		write500Error(w, err)
		return
	}

	// 生成私钥
	privateKey, err := generateKey(requestBody.ECC)
	if err != nil {
		write500Error(w, err)
		return
	}

	// 编码私钥为 PKCS8 格式
	privPKCS8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		write500Error(w, err)
		return
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
			write400String(w, fmt.Sprint("Error: SAN line ", i, " is invalid!"))
			return
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
		write500Error(w, err)
		return
	}

	// 解析新证书
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		write500Error(w, err)
		return
	}

	// 编码为 PKCS12 格式
	p12, err := pkcs12.Legacy.Encode(
		privateKey,
		cert,
		nil,
		requestBody.P12Key,
	)
	if err != nil {
		write500Error(w, err)
		return
	}

	// 构建响应
	responseBody := &struct {
		Cert string // PEM
		Key  string // PEM
		P12  string // Base64
		Time int64  // UnixMilli
	}{
		Cert: certToPEM(certDER),
		Key:  pkcs8ToPEM(privPKCS8),
		P12:  base64.StdEncoding.EncodeToString(p12),
		Time: Time.UnixMilli(),
	}
	write200JSON(w, responseBody)
}
