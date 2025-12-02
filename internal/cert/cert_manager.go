package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/config"
)

type Manager struct {
	ca     *x509.Certificate
	caKey  *rsa.PrivateKey
	certs  map[string]*tls.Certificate
	mu     sync.RWMutex
	caFile string
}

func NewCertManager(cfg *config.Config) (*Manager, error) {
	cm := &Manager{
		certs:  make(map[string]*tls.Certificate),
		caFile: cfg.Cert.CertFile,
	}

	if err := cm.loadCA(); err != nil {
		if err := cm.generateCA(); err != nil {
			return nil, err
		}
	}

	return cm, nil
}

func (cm *Manager) generateCA() error {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization: []string{"Hackerecon Proxy CA"},
			CommonName:   "Hackerecon Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}

	os.MkdirAll(filepath.Dir(cm.caFile), 0755)

	certOut, err := os.Create(cm.caFile)
	if err != nil {
		return err
	}
	defer certOut.Close()

	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})

	keyOut, err := os.Create(filepath.Join(filepath.Dir(cm.caFile), "ca-key.pem"))
	if err != nil {
		return err
	}
	defer keyOut.Close()

	pem.Encode(
		keyOut, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(caKey),
		},
	)

	cm.ca = ca
	cm.caKey = caKey

	return nil
}

func (cm *Manager) loadCA() error {
	certPEM, err := os.ReadFile(cm.caFile)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return err
	}

	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	keyPEM, err := os.ReadFile(filepath.Join(filepath.Dir(cm.caFile), "ca-key.pem"))
	if err != nil {
		return err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return err
	}

	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}

	cm.ca = ca
	cm.caKey = caKey

	return nil
}

func (cm *Manager) GetCertificate(host string) (*tls.Certificate, error) {
	cm.mu.RLock()
	if cert, ok := cm.certs[host]; ok {
		cm.mu.RUnlock()
		return cert, nil
	}
	cm.mu.RUnlock()

	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cert, ok := cm.certs[host]; ok {
		return cert, nil
	}

	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Hackerecon Proxy"},
			CommonName:   host,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0), // 1 год
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, cm.ca, &certKey.PublicKey, cm.caKey)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certBytes, cm.ca.Raw},
		PrivateKey:  certKey,
	}

	cm.certs[host] = cert

	return cert, nil
}

func (cm *Manager) GetCAPath() string {
	return cm.caFile
}
