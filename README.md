# FTPS Implementation for Go

## Information
This implementation does not implement the full FTP/FTPS specification. Only a small subset.

## Installation
	go get github.com/marcobeierer/ftps

## Usage
	ftps := new(FTPS)

	err := ftps.Connect("localhost", 21)
	if err != nil {
		panic(err)
	}

	err = ftps.Login("username", "password")
	if err != nil {
		panic(err)
	}

	directory, err := ftps.PrintWorkingDirectory()
	if err != nil {
		panic(err)
	}
	log.Printf("Current working directory: %s", directory)

	// Verify or keep alive an idle control connection.
	if err := ftps.Noop(); err != nil {
		panic(err)
	}

	err = ftps.Quit()
	if err != nil {
		panic(err)
	}

### Implicit FTPS

For servers that establish TLS immediately, commonly on port 990, use
`ConnectImplicit` instead of `Connect`:

	err := ftps.ConnectImplicit("localhost", 990)
	if err != nil {
		panic(err)
	}

### Custom connections and proxies

Set `Dialer` to control how both the FTPS control and passive data connections
are established:

	ftps.Dialer = &net.Dialer{Timeout: 10 * time.Second}

Any type with a `Dial(network, address string) (net.Conn, error)` method can be
used. This includes SOCKS dialers from `golang.org/x/net/proxy`.

The default timeout for connection establishment and each subsequent network
operation is 30 seconds. Set `Timeout` to another duration when needed. Custom
dialers that implement `DialContext` use this timeout during connection
establishment; other custom dialers are responsible for their own dial timeout.

### TLS verification

Server certificates are verified against the connection hostname and the
system certificate pool by default. For a private certificate authority, add
that authority to `TLSConfig.RootCAs`. Do not use `InsecureSkipVerify` in
production.

### Resource limits

Control responses, directory listings, listing lines, and files returned by
`RetrieveFileData` have conservative default size limits. Configure
`MaxControlResponseSize`, `MaxListSize`, `MaxListLineSize`, or
`MaxRetrieveSize` when larger values are required. Use `RetrieveWriter` to
download large files without buffering them in memory.

### Streaming transfers

Use `StoreReader` and `RetrieveWriter` to transfer data without buffering the
entire file in memory:

	if err := ftps.StoreReader("remote.dat", source); err != nil {
		panic(err)
	}

	if err := ftps.RetrieveWriter("remote.dat", destination); err != nil {
		panic(err)
	}

## Testing
Run the default test suite with:

	go test ./...

The tests start an in-process explicit FTPS server with temporary storage and a self-signed certificate. No external FTPS server or environment variable is required.

The `github.com/fclairamb/ftpserverlib` and `github.com/spf13/afero` dependencies are used only by the test files to provide this server and its temporary filesystem. They are not used by the FTPS client at runtime.

## Credits
This work was inspired by the work of jlaffaye (https://github.com/jlaffaye/ftp) and smallfish (https://github.com/smallfish/ftp).
