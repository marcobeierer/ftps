package ftps

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseEntryLine(t *testing.T) {
	tests := []struct {
		name      string
		line      string
		entryType EntryType
		size      uint64
		entryName string
		wantTime  time.Time
	}{
		{"file", "-rw-r--r-- 1 owner group 123 Jan 02 15:04 file.txt", EntryTypeFile, 123, "file.txt", time.Date(time.Now().Year(), time.January, 2, 15, 4, 0, 0, time.UTC)},
		{"directory", "drwxr-xr-x 2 owner group 0 Dec 31 2020 directory", EntryTypeFolder, 0, "directory", time.Date(2020, time.December, 31, 0, 0, 0, 0, time.UTC)},
		{"link", "lrwxrwxrwx 1 owner group 7 Jan 02 2020 link -> target", EntryTypeLink, 7, "link -> target", time.Date(2020, time.January, 2, 0, 0, 0, 0, time.UTC)},
		{"spaces", "-rw-r--r-- 1 owner group 9 Jan 02 15:04 file with spaces.txt", EntryTypeFile, 9, "file with spaces.txt", time.Date(time.Now().Year(), time.January, 2, 15, 4, 0, 0, time.UTC)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry, err := (&FTPS{}).parseEntryLine(test.line)
			if err != nil {
				t.Fatalf("parseEntryLine: %v", err)
			}
			if entry.Type != test.entryType || entry.Size != test.size || entry.Name != test.entryName {
				t.Fatalf("entry = %#v, want type=%v size=%d name=%q", entry, test.entryType, test.size, test.entryName)
			}
			if !entry.Time.Equal(test.wantTime) {
				t.Errorf("entry time = %v, want %v", entry.Time, test.wantTime)
			}
		})
	}
}

func TestParseEntryLineMalformedDoesNotPanic(t *testing.T) {
	for _, line := range []string{
		"",
		"-rw-r--r-- 1 owner group 1 Jan 02",
		"?rw-r--r-- 1 owner group 1 Jan 02 15:04 file",
		"-rw-r--r-- 1 owner group not-a-size Jan 02 15:04 file",
		"-rw-r--r-- 1 owner group 1 NotAMonth 02 2020 file",
		"-rw-r--r-- 1 owner group 1 Jan 02 2 file",
	} {
		t.Run(line, func(t *testing.T) {
			entry, err, recovered := parseEntryLineSafely(line)
			if recovered != nil {
				t.Fatalf("parseEntryLine panicked: %v", recovered)
			}
			if err == nil || entry != nil {
				t.Fatalf("parseEntryLine(%q) = entry=%#v err=%v, want error", line, entry, err)
			}
		})
	}
}

func parseEntryLineSafely(line string) (entry *Entry, err error, recovered any) {
	defer func() { recovered = recover() }()
	entry, err = (&FTPS{}).parseEntryLine(line)
	return
}

func TestPASV(t *testing.T) {
	tests := []struct {
		name     string
		response string
		wantPort int
		wantErr  bool
	}{
		{"valid", "227 Entering Passive Mode (127,0,0,1,195,80)\r\n", 50000, false},
		{"missing parentheses", "227 Entering Passive Mode\r\n", 0, true},
		{"too few fields", "227 Entering Passive Mode (127,0,0,1,195)\r\n", 0, true},
		{"too many fields", "227 Entering Passive Mode (127,0,0,1,195,80,1)\r\n", 0, true},
		{"invalid port", "227 Entering Passive Mode (127,0,0,1,no,80)\r\n", 0, true},
		{"port component too large", "227 Entering Passive Mode (127,0,0,1,256,1)\r\n", 0, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()
			go func() {
				_, _ = bufio.NewReader(serverConn).ReadString('\n')
				_, _ = serverConn.Write([]byte(test.response))
			}()
			client := &FTPS{conn: clientConn, text: textproto.NewConn(clientConn)}
			port, err, recovered := pasvSafely(client)
			if recovered != nil {
				t.Fatalf("pasv panicked: %v", recovered)
			}
			if (err != nil) != test.wantErr || (!test.wantErr && port != test.wantPort) {
				t.Fatalf("pasv() = %d, %v; want %d, error=%v", port, err, test.wantPort, test.wantErr)
			}
		})
	}
}

func TestListIncludesFinalLineWithoutNewline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	clientControl, serverControl := net.Pipe()
	defer clientControl.Close()
	defer serverControl.Close()

	certificate := newTestCertificate(t)
	serverErr := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(serverControl)
		if line, err := reader.ReadString('\n'); err != nil || line != "PASV\r\n" {
			serverErr <- fmt.Errorf("read PASV = %q, %v", line, err)
			return
		}

		port := listener.Addr().(*net.TCPAddr).Port
		if _, err := fmt.Fprintf(serverControl, "227 Entering Passive Mode (127,0,0,1,%d,%d)\r\n", port/256, port%256); err != nil {
			serverErr <- err
			return
		}
		dataConn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}

		if line, err := reader.ReadString('\n'); err != nil || line != "LIST -a\r\n" {
			_ = dataConn.Close()
			serverErr <- fmt.Errorf("read LIST = %q, %v", line, err)
			return
		}
		if _, err := serverControl.Write([]byte("150 Opening data connection\r\n")); err != nil {
			_ = dataConn.Close()
			serverErr <- err
			return
		}

		tlsConn := tls.Server(dataConn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
		if err := tlsConn.Handshake(); err != nil {
			_ = tlsConn.Close()
			serverErr <- err
			return
		}
		if _, err := tlsConn.Write([]byte("-rw-r--r-- 1 owner group 4 Jan 02 2020 final.txt")); err != nil {
			_ = tlsConn.Close()
			serverErr <- err
			return
		}
		if err := tlsConn.Close(); err != nil {
			serverErr <- err
			return
		}
		_, err = serverControl.Write([]byte("226 Transfer complete\r\n"))
		serverErr <- err
	}()

	client := &FTPS{
		host:      "127.0.0.1",
		conn:      clientControl,
		text:      textproto.NewConn(clientControl),
		TLSConfig: tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test certificate is self-signed
	}
	entries, err := client.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("scripted server: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "final.txt" {
		t.Fatalf("List entries = %#v, want final.txt", entries)
	}
}

func TestStoreFilePreliminaryResponse(t *testing.T) {
	for _, test := range []struct {
		name    string
		code    int
		wantErr bool
	}{
		{"data connection open", 125, false},
		{"restart marker", 110, true},
		{"service not ready", 120, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer listener.Close()

			clientControl, serverControl := net.Pipe()
			defer clientControl.Close()
			defer serverControl.Close()

			certificate := newTestCertificate(t)
			serverErr := make(chan error, 1)
			go func() {
				reader := bufio.NewReader(serverControl)
				if line, err := reader.ReadString('\n'); err != nil || line != "PASV\r\n" {
					serverErr <- fmt.Errorf("read PASV = %q, %v", line, err)
					return
				}

				port := listener.Addr().(*net.TCPAddr).Port
				if _, err := fmt.Fprintf(serverControl, "227 Entering Passive Mode (127,0,0,1,%d,%d)\r\n", port/256, port%256); err != nil {
					serverErr <- err
					return
				}
				dataConn, err := listener.Accept()
				if err != nil {
					serverErr <- err
					return
				}

				if line, err := reader.ReadString('\n'); err != nil || line != "STOR test.txt\r\n" {
					_ = dataConn.Close()
					serverErr <- fmt.Errorf("read STOR = %q, %v", line, err)
					return
				}
				if _, err := fmt.Fprintf(serverControl, "%d preliminary response\r\n", test.code); err != nil {
					_ = dataConn.Close()
					serverErr <- err
					return
				}
				if test.wantErr {
					serverErr <- dataConn.Close()
					return
				}

				tlsConn := tls.Server(dataConn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
				if err := tlsConn.Handshake(); err != nil {
					_ = tlsConn.Close()
					serverErr <- err
					return
				}
				data, err := io.ReadAll(tlsConn)
				if err != nil {
					_ = tlsConn.Close()
					serverErr <- err
					return
				}
				if string(data) != "payload" {
					_ = tlsConn.Close()
					serverErr <- fmt.Errorf("stored data = %q, want payload", data)
					return
				}
				if err := tlsConn.Close(); err != nil {
					serverErr <- err
					return
				}
				_, err = serverControl.Write([]byte("226 Transfer complete\r\n"))
				serverErr <- err
			}()

			client := &FTPS{
				host:      "127.0.0.1",
				conn:      clientControl,
				text:      textproto.NewConn(clientControl),
				TLSConfig: tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test certificate is self-signed
			}
			err = client.StoreFile("test.txt", []byte("payload"))
			if (err != nil) != test.wantErr {
				t.Fatalf("StoreFile error = %v, want error=%v", err, test.wantErr)
			}
			if err := <-serverErr; err != nil {
				t.Fatalf("scripted server: %v", err)
			}
		})
	}
}

func pasvSafely(client *FTPS) (port int, err error, recovered any) {
	defer func() { recovered = recover() }()
	port, err = client.pasv()
	return
}

func TestFTPS(t *testing.T) {
	serverPort := newTestFTPServer(t)

	client := new(FTPS)
	client.TLSConfig = tls.Config{InsecureSkipVerify: true} //nolint:gosec // test certificate is self-signed

	if err := client.Connect("127.0.0.1", serverPort); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := client.Login("ftptester", "ftptester"); err != nil {
		t.Fatalf("Login: %v", err)
	}

	workingDirectory, err := client.PrintWorkingDirectory()
	if err != nil {
		t.Fatalf("PWD: %v", err)
	}
	if !strings.Contains(workingDirectory, "/") {
		t.Fatalf("PWD = %q, want a root directory", workingDirectory)
	}

	if err := client.MakeDirectory("websites"); err != nil {
		t.Fatalf("MakeDirectory: %v", err)
	}
	if err := client.ChangeWorkingDirectory("websites"); err != nil {
		t.Fatalf("ChangeWorkingDirectory into websites: %v", err)
	}
	if err := client.ChangeWorkingDirectory(".."); err != nil {
		t.Fatalf("ChangeWorkingDirectory to parent: %v", err)
	}
	if err := client.RemoveDirectory("websites"); err != nil {
		t.Fatalf("RemoveDirectory: %v", err)
	}

	want := []byte("self-contained explicit FTPS test")
	if err := client.StoreFile("test.txt", want); err != nil {
		t.Fatalf("StoreFile: %v", err)
	}
	got, err := client.RetrieveFileData("test.txt")
	if err != nil {
		t.Fatalf("RetrieveFileData: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("RetrieveFileData = %q, want %q", got, want)
	}

	localCopy := filepath.Join(t.TempDir(), "copy.txt")
	if err := client.RetrieveFile("test.txt", localCopy); err != nil {
		t.Fatalf("RetrieveFile: %v", err)
	}
	copyData, err := os.ReadFile(localCopy)
	if err != nil {
		t.Fatalf("read retrieved file: %v", err)
	}
	if string(copyData) != string(want) {
		t.Fatalf("retrieved file = %q, want %q", copyData, want)
	}

	entries, err := client.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, entry := range entries {
		if entry.Name == "test.txt" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("List did not contain test.txt: %v", entries)
	}

	if err := client.DeleteFile("test.txt"); err != nil {
		t.Fatalf("DeleteFile: %v", err)
	}
	if err := client.Quit(); err != nil {
		t.Fatalf("Quit: %v", err)
	}
}

func newLoggedInClient(t *testing.T) *FTPS {
	t.Helper()
	client := &FTPS{TLSConfig: tls.Config{InsecureSkipVerify: true}} //nolint:gosec // test certificate is self-signed
	if err := client.Connect("127.0.0.1", newTestFTPServer(t)); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := client.Login("ftptester", "ftptester"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	t.Cleanup(func() {
		if client.conn != nil {
			_ = client.conn.Close()
		}
	})
	return client
}

func TestLoginRejectsInvalidCredentials(t *testing.T) {
	client := &FTPS{TLSConfig: tls.Config{InsecureSkipVerify: true}} //nolint:gosec // test certificate is self-signed
	if err := client.Connect("127.0.0.1", newTestFTPServer(t)); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := client.Login("wrong", "credentials"); err == nil {
		t.Fatal("Login succeeded with invalid credentials")
	}
}

func TestLoginPreservesPercentInPassword(t *testing.T) {
	const (
		username = "percent-tester"
		password = "a%b"
	)

	client := &FTPS{TLSConfig: tls.Config{InsecureSkipVerify: true}} //nolint:gosec // test certificate is self-signed
	if err := client.Connect("127.0.0.1", newTestFTPServerWithCredentials(t, username, password)); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := client.Login(username, password); err != nil {
		t.Fatalf("Login with percent in password: %v", err)
	}
}

func TestRequestRejectsCommandInjection(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	client := &FTPS{conn: clientConn, text: textproto.NewConn(clientConn)}

	if _, err := client.request("CWD safe\r\nDELE important.txt", 250); !errors.Is(err, errCommandContainsNewline) {
		t.Fatalf("request error = %v, want %v", err, errCommandContainsNewline)
	}
}

func TestDebugRedactsPassword(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	serverErr := make(chan error, 1)
	go func() {
		line, err := bufio.NewReader(serverConn).ReadString('\n')
		if err == nil && line != "PASS top-secret\r\n" {
			err = fmt.Errorf("command = %q, want PASS command", line)
		}
		if err == nil {
			_, err = serverConn.Write([]byte("230 logged in\r\n"))
		}
		serverErr <- err
	}()

	var output bytes.Buffer
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	previousPrefix := log.Prefix()
	log.SetOutput(&output)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
		log.SetPrefix(previousPrefix)
	})

	client := &FTPS{Debug: true, conn: clientConn, text: textproto.NewConn(clientConn)}
	if _, err := client.request("PASS top-secret", 230); err != nil {
		t.Fatalf("request: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("scripted server: %v", err)
	}
	if strings.Contains(output.String(), "top-secret") {
		t.Fatalf("debug output exposed password: %q", output.String())
	}
	if !strings.Contains(output.String(), "PASS <redacted>") {
		t.Fatalf("debug output = %q, want redacted PASS command", output.String())
	}
}

func TestNoop(t *testing.T) {
	client := newLoggedInClient(t)
	if err := client.Noop(); err != nil {
		t.Fatalf("Noop: %v", err)
	}
}

func TestConnectRejectsUntrustedCertificate(t *testing.T) {
	client := new(FTPS)
	if err := client.Connect("127.0.0.1", newTestFTPServer(t)); err == nil {
		t.Fatal("Connect succeeded with an untrusted certificate")
	}
}

func TestConnectUsesHostForCertificateVerification(t *testing.T) {
	certificate := newTestCertificate(t)
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatalf("parse test certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	client := &FTPS{TLSConfig: tls.Config{RootCAs: roots}}
	port := newTestFTPServerWithCertificate(t, "ftptester", "ftptester", certificate)
	if err := client.Connect("127.0.0.1", port); err != nil {
		t.Fatalf("Connect with trusted certificate: %v", err)
	}
	if client.TLSConfig.ServerName != "" {
		t.Fatalf("Connect mutated TLSConfig.ServerName to %q", client.TLSConfig.ServerName)
	}
	if err := client.Quit(); err != nil {
		t.Fatalf("Quit: %v", err)
	}
}

func TestResponseSizeLimit(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	client := &FTPS{
		conn:                   clientConn,
		text:                   textproto.NewConn(clientConn),
		MaxControlResponseSize: 16,
	}
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		_, _ = serverConn.Write([]byte("220 " + strings.Repeat("x", 32) + "\r\n"))
	}()

	_, err := client.response(220)
	if !errors.Is(err, errResponseTooLarge) {
		t.Fatalf("response error = %v, want %v", err, errResponseTooLarge)
	}
	if _, err := client.request("NOOP", 200); err == nil {
		t.Fatal("request succeeded after an oversized response invalidated the connection")
	}
	_ = clientConn.Close()
	_ = serverConn.Close()
	<-serverDone
}

func TestMultilineResponse(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	go func() {
		_, _ = serverConn.Write([]byte("220-first line\r\nsecond line\r\n220 last line\r\n"))
	}()

	client := &FTPS{conn: clientConn, text: textproto.NewConn(clientConn)}
	message, err := client.response(220)
	if err != nil {
		t.Fatalf("response: %v", err)
	}
	if want := "first line\nsecond line\nlast line"; message != want {
		t.Fatalf("response message = %q, want %q", message, want)
	}
}

func TestResponseTimeout(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	client := &FTPS{
		conn:    clientConn,
		text:    textproto.NewConn(clientConn),
		Timeout: 10 * time.Millisecond,
	}

	if _, err := client.response(220); err == nil {
		t.Fatal("response succeeded without server data")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("response error = %v, want timeout", err)
	}
}

func TestTLSHandshakeTimeout(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	client := &FTPS{
		host:      "localhost",
		TLSConfig: tls.Config{InsecureSkipVerify: true}, //nolint:gosec // no certificate is exchanged
		Timeout:   10 * time.Millisecond,
	}

	if _, err := client.upgradeConnToTLS(clientConn); err == nil {
		t.Fatal("TLS handshake succeeded without a server response")
	}
}

func TestConnectImplicitStartsTLSBeforeGreeting(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	certificate := newTestCertificate(t)
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		tlsConn := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
		})
		defer tlsConn.Close()
		if err := tlsConn.Handshake(); err != nil {
			serverErr <- err
			return
		}
		if _, err := tlsConn.Write([]byte("220 implicit FTPS ready\r\n")); err != nil {
			serverErr <- err
			return
		}
		line, err := bufio.NewReader(tlsConn).ReadString('\n')
		if err != nil {
			serverErr <- err
			return
		}
		if line != "QUIT\r\n" {
			serverErr <- fmt.Errorf("command = %q, want QUIT", line)
			return
		}
		_, err = tlsConn.Write([]byte("221 goodbye\r\n"))
		serverErr <- err
	}()

	dialer := new(recordingDialer)
	client := &FTPS{
		Dialer:    dialer,
		TLSConfig: tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test certificate is self-signed
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := client.ConnectImplicit("127.0.0.1", port); err != nil {
		t.Fatalf("ConnectImplicit: %v", err)
	}
	if err := client.Quit(); err != nil {
		t.Fatalf("Quit: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("implicit FTPS server: %v", err)
	}
	wantAddress := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	if len(dialer.addresses) != 1 || dialer.addresses[0] != wantAddress {
		t.Fatalf("Dial called for %v, want [%s]", dialer.addresses, wantAddress)
	}
}

func TestRetrieveFileDataMissingRemoteFile(t *testing.T) {
	client := newLoggedInClient(t)
	if data, err := client.RetrieveFileData("missing.txt"); err == nil || data != nil {
		t.Fatalf("RetrieveFileData missing file = %q, %v; want error", data, err)
	}
}

func TestRetrieveFileDataSizeLimit(t *testing.T) {
	client := newLoggedInClient(t)
	if err := client.StoreFile("large.txt", []byte("large")); err != nil {
		t.Fatalf("StoreFile: %v", err)
	}
	client.MaxRetrieveSize = 4
	if data, err := client.RetrieveFileData("large.txt"); !errors.Is(err, errRetrieveTooLarge) || data != nil {
		t.Fatalf("RetrieveFileData = %q, %v; want nil, %v", data, err, errRetrieveTooLarge)
	}
	if err := client.Noop(); err != nil {
		t.Fatalf("Noop after size limit: %v", err)
	}
}

func TestListSizeLimit(t *testing.T) {
	client := newLoggedInClient(t)
	if err := client.StoreFile("listed.txt", []byte("payload")); err != nil {
		t.Fatalf("StoreFile: %v", err)
	}
	client.MaxListSize = 1
	if _, err := client.List(); !errors.Is(err, errListTooLarge) {
		t.Fatalf("List error = %v, want %v", err, errListTooLarge)
	}
	if err := client.Noop(); err != nil {
		t.Fatalf("Noop after list size limit: %v", err)
	}
}

func TestListLineSizeLimit(t *testing.T) {
	client := newLoggedInClient(t)
	name := strings.Repeat("x", 128)
	if err := client.StoreFile(name, []byte("payload")); err != nil {
		t.Fatalf("StoreFile: %v", err)
	}
	client.MaxListLineSize = 32
	if _, err := client.List(); err == nil {
		t.Fatal("List succeeded with a line over the configured limit")
	}
	if err := client.Noop(); err != nil {
		t.Fatalf("Noop after list line size limit: %v", err)
	}
}

func TestRetrieveFileLocalCreationFailure(t *testing.T) {
	client := newLoggedInClient(t)
	if err := client.StoreFile("existing.txt", []byte("payload")); err != nil {
		t.Fatalf("StoreFile: %v", err)
	}
	path := filepath.Join(t.TempDir(), "missing", "copy.txt")
	if err := client.RetrieveFile("existing.txt", path); err == nil {
		t.Fatal("RetrieveFile succeeded when local parent directory was missing")
	}
}

func TestStoreAndRetrievePayloads(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload []byte
	}{
		{"empty", nil},
		{"binary", []byte{0, 1, 2, 127, 128, 254, 255}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := newLoggedInClient(t)
			if err := client.StoreFile(test.name, test.payload); err != nil {
				t.Fatalf("StoreFile: %v", err)
			}
			got, err := client.RetrieveFileData(test.name)
			if err != nil {
				t.Fatalf("RetrieveFileData: %v", err)
			}
			if !bytes.Equal(got, test.payload) {
				t.Fatalf("RetrieveFileData = %v, want %v", got, test.payload)
			}
		})
	}
}

type recordingDialer struct {
	addresses []string
}

type dialFunc func(network, address string) (net.Conn, error)

func (f dialFunc) Dial(network, address string) (net.Conn, error) {
	return f(network, address)
}

type blockingContextDialer struct {
	usedDialContext bool
}

func (d *blockingContextDialer) Dial(_, _ string) (net.Conn, error) {
	return nil, errors.New("Dial called instead of DialContext")
}

func (d *blockingContextDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	d.usedDialContext = true
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestCustomDialContextTimeout(t *testing.T) {
	dialer := new(blockingContextDialer)
	client := &FTPS{Dialer: dialer, Timeout: 10 * time.Millisecond}
	_, err := client.dial("tcp", "example.com:21")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dial error = %v, want %v", err, context.DeadlineExceeded)
	}
	if !dialer.usedDialContext {
		t.Fatal("DialContext was not used")
	}
}

func TestOpenDataConnUsesPinnedControlAddress(t *testing.T) {
	var gotAddress string
	client := &FTPS{
		host:     "ftp.example",
		dataHost: "192.0.2.10",
		Dialer: dialFunc(func(_, address string) (net.Conn, error) {
			gotAddress = address
			return nil, errors.New("stop after recording address")
		}),
	}

	_, _ = client.openDataConn(2121)
	if want := "192.0.2.10:2121"; gotAddress != want {
		t.Fatalf("data connection address = %q, want %q", gotAddress, want)
	}
}

func (d *recordingDialer) Dial(network, address string) (net.Conn, error) {
	d.addresses = append(d.addresses, address)
	return net.Dial(network, address)
}

func TestCustomDialerHandlesControlAndDataConnections(t *testing.T) {
	dialer := new(recordingDialer)
	client := &FTPS{
		Dialer:    dialer,
		TLSConfig: tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test certificate is self-signed
	}
	serverPort := newTestFTPServer(t)

	if err := client.Connect("127.0.0.1", serverPort); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := client.Login("ftptester", "ftptester"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if err := client.StoreFile("dialed.txt", []byte("payload")); err != nil {
		t.Fatalf("StoreFile: %v", err)
	}
	if err := client.Quit(); err != nil {
		t.Fatalf("Quit: %v", err)
	}

	if len(dialer.addresses) != 2 {
		t.Fatalf("Dial called for %v, want control and data connections", dialer.addresses)
	}
	wantControl := net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort))
	if dialer.addresses[0] != wantControl {
		t.Errorf("control address = %q, want %q", dialer.addresses[0], wantControl)
	}
	if host, _, err := net.SplitHostPort(dialer.addresses[1]); err != nil || host != "127.0.0.1" {
		t.Errorf("data address = %q, want 127.0.0.1 with a passive port", dialer.addresses[1])
	}
}

func TestStoreReaderAndRetrieveWriter(t *testing.T) {
	client := newLoggedInClient(t)
	want := bytes.Repeat([]byte("streamed FTPS payload\n"), 8192)

	if err := client.StoreReader("streamed.txt", bytes.NewReader(want)); err != nil {
		t.Fatalf("StoreReader: %v", err)
	}

	var got bytes.Buffer
	if err := client.RetrieveWriter("streamed.txt", &got); err != nil {
		t.Fatalf("RetrieveWriter: %v", err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("RetrieveWriter wrote %d bytes, want %d", got.Len(), len(want))
	}
}
