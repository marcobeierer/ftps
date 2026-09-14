# FTPS Implementation for Go

## Information
This implementation does not implement the full FTP/FTPS specification. Only a small subset.

I have not done a security review of the code, yet. Therefore no guarantee is given. It would be nice if somebody could do a security review and report back if the implementation is vulnerable.

## Installation
	go get github.com/marcobeierer/ftps

## Usage
	ftps := new(FTPS)

	ftps.TLSConfig.InsecureSkipVerify = true // often necessary in shared hosting environments
	ftps.Debug = true

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

	err = ftps.Quit()
	if err != nil {
		panic(err)
	}

### Custom connections and proxies

Set `Dialer` to control how both the FTPS control and passive data connections
are established:

	ftps.Dialer = &net.Dialer{Timeout: 10 * time.Second}

Any type with a `Dial(network, address string) (net.Conn, error)` method can be
used. This includes SOCKS dialers from `golang.org/x/net/proxy`.

## Testing
Run the default test suite with:

	go test ./...

The tests start an in-process explicit FTPS server with temporary storage and a self-signed certificate. No external FTPS server or environment variable is required.

The `github.com/fclairamb/ftpserverlib` and `github.com/spf13/afero` dependencies are used only by the test files to provide this server and its temporary filesystem. They are not used by the FTPS client at runtime.

## Credits
This work was inspired by the work of jlaffaye (https://github.com/jlaffaye/ftp) and smallfish (https://github.com/smallfish/ftp).
