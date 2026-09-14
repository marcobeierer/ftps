package ftps

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
