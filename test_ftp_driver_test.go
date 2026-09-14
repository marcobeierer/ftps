package ftps

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	ftpserver "github.com/fclairamb/ftpserverlib"
	"github.com/spf13/afero"
)

type testFTPDriver struct {
	fs       afero.Fs
	cert     tls.Certificate
	settings *ftpserver.Settings
}

func newTestFTPServer(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for test FTP server: %v", err)
	}
	driver := &testFTPDriver{
		fs:   afero.NewBasePathFs(afero.NewOsFs(), t.TempDir()),
		cert: newTestCertificate(t),
		settings: &ftpserver.Settings{
			Listener:    listener,
			PublicHost:  "127.0.0.1",
			TLSRequired: ftpserver.MandatoryEncryption,
		},
	}
	server := ftpserver.NewFtpServer(driver)
	if err := server.Listen(); err != nil {
		_ = listener.Close()
		t.Fatalf("start test FTP server: %v", err)
	}
	serveDone := make(chan struct{})
	t.Cleanup(func() {
		if err := server.Stop(); err != nil && !errors.Is(err, ftpserver.ErrNotListening) {
			t.Errorf("stop test FTP server: %v", err)
		}
		<-serveDone
	})
	go func() {
		defer close(serveDone)
		_ = server.Serve()
	}()

	return listener.Addr().(*net.TCPAddr).Port
}

var _ ftpserver.MainDriver = (*testFTPDriver)(nil)

func (d *testFTPDriver) GetSettings() (*ftpserver.Settings, error) {
	return d.settings, nil
}

func (d *testFTPDriver) ClientConnected(ftpserver.ClientContext) (string, error) {
	return "test FTPS server", nil
}

func (d *testFTPDriver) ClientDisconnected(ftpserver.ClientContext) {}

func (d *testFTPDriver) AuthUser(_ ftpserver.ClientContext, user, pass string) (ftpserver.ClientDriver, error) {
	if user != "ftptester" || pass != "ftptester" {
		return nil, errors.New("invalid test credentials")
	}
	return d.fs, nil
}

func (d *testFTPDriver) GetTLSConfig() (*tls.Config, error) {
	return &tls.Config{Certificates: []tls.Certificate{d.cert}, MinVersion: tls.VersionTLS12}, nil
}

func newTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test TLS key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate test TLS serial: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test TLS certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load test TLS certificate: %v", err)
	}
	return certificate
}
