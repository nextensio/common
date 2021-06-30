package common

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/google/gopacket"
)

const (
	GENERAL_ERR = 1 + iota
	CONNECTION_ERR
)

type OnboardInfo struct {
	Userid   string
	Uniqueid string
	GwIP     string
	GwName   string
	GwPort   int
	Services []string
	CaCert   []byte
}

type FlowKey struct {
	Xfor  string
	Sport uint32
	Dport uint32
	Proto uint32
}

type NxtError struct {
	action int
	Err    error
}

func (n *NxtError) Error() string {
	var err string = "nil"
	if n.Err != nil {
		err = n.Err.Error()
	}
	return err + ":" + fmt.Sprint(n.action)
}

func Err(action int, err error) *NxtError {
	return &NxtError{action: action, Err: err}
}

var (
	errBlockIsNotPrivateKey  = errors.New("block is not a private key, unable to load key")
	errUnknownKeyTime        = errors.New("unknown key time in PKCS#8 wrapping, unable to load key")
	errNoPrivateKeyFound     = errors.New("no private key found, unable to load key")
	errBlockIsNotCertificate = errors.New("block is not a certificate, unable to load certificates")
	errNoCertificateFound    = errors.New("no certificate found, unable to load certificates")
)

// LoadCertificate Load/read certificate(s) from file
func LoadCertificate(rawData []byte) (*tls.Certificate, error) {

	var certificate tls.Certificate

	for {
		block, rest := pem.Decode(rawData)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			return nil, errBlockIsNotCertificate
		}

		certificate.Certificate = append(certificate.Certificate, block.Bytes)
		rawData = rest
	}

	if len(certificate.Certificate) == 0 {
		return nil, errNoCertificateFound
	}

	return &certificate, nil
}

// LoadKey Load/read key from file
func LoadKey(rawData []byte) (crypto.PrivateKey, error) {

	block, _ := pem.Decode(rawData)
	if block == nil || !strings.HasSuffix(block.Type, "PRIVATE KEY") {
		return nil, errBlockIsNotPrivateKey
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errUnknownKeyTime
		}
	}

	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, errNoPrivateKeyFound
}

// LoadKeyAndCertificate reads certificates or key from file
func LoadKeyAndCertificate(pvtKey []byte, pubKey []byte) (*tls.Certificate, error) {
	privateKey, err := LoadKey(pvtKey)
	if err != nil {
		return nil, err
	}

	certificate, err := LoadCertificate(pubKey)
	if err != nil {
		return nil, err
	}

	certificate.PrivateKey = privateKey

	return certificate, nil
}

// A fixed size buffer with room at the head and tail to append/prepend
// Asking for more room than available in the fixed size results in error
type InplaceSerialize struct {
	data   []byte
	start  int
	layers []gopacket.LayerType
}

func (w *InplaceSerialize) Bytes() []byte {
	return w.data[w.start:]
}

func (w *InplaceSerialize) PrependBytes(num int) ([]byte, error) {
	if num < 0 {
		panic("num < 0")
	}
	if num > w.start {
		panic("OOHeadroom")
	}
	w.start -= num
	return w.data[w.start : w.start+num], nil
}

func (w *InplaceSerialize) AppendBytes(num int) ([]byte, error) {
	panic("append not supported")
}

func (w *InplaceSerialize) Clear() error {
	// We dont really support reusing the same serialize buffer,
	// but gopacket calls Clear() everytime we ask to serialize,
	// so just do nothing here
	return nil
}

func (w *InplaceSerialize) Layers() []gopacket.LayerType {
	return w.layers
}

func (w *InplaceSerialize) PushLayer(l gopacket.LayerType) {
	w.layers = append(w.layers, l)
}

func NewInplaceSerializeBuffer(data []byte, start int) gopacket.SerializeBuffer {
	return &InplaceSerialize{data: data, start: start}
}

// All the yaml files add nxt- to the tenant name to prevent a tenant name from
// clashing with an existing k8s service like 'prometheus'
func TenantToNamespace(tenant string) string {
	return "nxt-" + tenant
}

func NamespaceToTenant(ns string) string {
	return ns[4:]
}
