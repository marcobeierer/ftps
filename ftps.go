package ftps

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultTimeout is the default limit for each network operation.
	DefaultTimeout = 30 * time.Second
	// DefaultMaxControlResponseSize is the default maximum control response size.
	DefaultMaxControlResponseSize = 64 << 10
	// DefaultMaxListSize is the default maximum directory listing size.
	DefaultMaxListSize = 16 << 20
	// DefaultMaxListLineSize is the default maximum directory listing line size.
	DefaultMaxListLineSize = 64 << 10
	// DefaultMaxRetrieveSize is the default in-memory retrieval limit.
	DefaultMaxRetrieveSize = 100 << 20
)

var (
	errCommandContainsNewline = errors.New("ftp command contains a newline")
	errResponseTooLarge       = errors.New("ftp control response exceeds the configured limit")
	errListTooLarge           = errors.New("ftp directory listing exceeds the configured limit")
	errRetrieveTooLarge       = errors.New("retrieved file exceeds the configured in-memory limit")
)

// Dialer establishes network connections for an FTPS client.
type Dialer interface {
	Dial(network, address string) (net.Conn, error)
}

// FTPS is an FTPS client.
type FTPS struct {
	host     string
	dataHost string

	conn net.Conn
	text *textproto.Conn

	Debug     bool
	TLSConfig tls.Config
	Dialer    Dialer

	// Timeout limits each network connection, handshake, command, and transfer.
	// Zero uses DefaultTimeout. A negative value disables deadlines.
	Timeout time.Duration
	// MaxControlResponseSize limits each FTP control response in bytes.
	// Zero uses DefaultMaxControlResponseSize. A negative value disables the limit.
	MaxControlResponseSize int64
	// MaxListSize limits the total bytes read by List.
	// Zero uses DefaultMaxListSize. A negative value disables the limit.
	MaxListSize int64
	// MaxListLineSize limits one line read by List.
	// Zero uses DefaultMaxListLineSize. A negative value disables the limit.
	MaxListLineSize int
	// MaxRetrieveSize limits bytes buffered by RetrieveFileData.
	// Zero uses DefaultMaxRetrieveSize. A negative value disables the limit.
	MaxRetrieveSize int64
}

func (ftps *FTPS) Connect(host string, port int) error {
	return ftps.connect(host, port, false)
}

// ConnectImplicit connects to an implicit FTPS server where TLS is active
// immediately after the TCP connection is established.
func (ftps *FTPS) ConnectImplicit(host string, port int) error {
	return ftps.connect(host, port, true)
}

func (ftps *FTPS) connect(host string, port int, implicit bool) (err error) {
	ftps.host = host

	ftps.conn, err = ftps.dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	ftps.dataHost = host
	if remote, ok := ftps.conn.RemoteAddr().(*net.TCPAddr); ok {
		ftps.dataHost = remote.IP.String()
		if remote.Zone != "" {
			ftps.dataHost += "%" + remote.Zone
		}
	}

	if implicit {
		ftps.conn, err = ftps.upgradeConnToTLS(ftps.conn)
		if err != nil {
			ftps.conn = nil
			return err
		}
	}

	ftps.text = textproto.NewConn(ftps.conn)
	if _, err = ftps.response(220); err != nil {
		_ = ftps.conn.Close()
		ftps.conn = nil
		return err
	}

	if !implicit {
		if _, err = ftps.request("AUTH TLS", 234); err != nil {
			_ = ftps.conn.Close()
			ftps.conn = nil
			return err
		}
		ftps.conn, err = ftps.upgradeConnToTLS(ftps.conn)
		if err != nil {
			ftps.conn = nil
			return err
		}
		ftps.text = textproto.NewConn(ftps.conn) // TODO use sync or something similar?
	}

	return
}

func (ftps *FTPS) isConnEstablished() {

	if ftps.conn == nil {
		panic("Connection is not established yet")
	}
}

func (ftps *FTPS) Login(username, password string) (err error) {

	ftps.isConnEstablished()

	_, err = ftps.request(fmt.Sprintf("USER %s", username), 331)
	if err != nil {
		return err
	}

	_, err = ftps.request(fmt.Sprintf("PASS %s", password), 230)
	if err != nil {
		return err
	}

	_, err = ftps.request("TYPE I", 200) // use binary mode
	if err != nil {
		return err
	}

	_, err = ftps.request("PBSZ 0", 200)
	if err != nil {
		return err
	}

	_, err = ftps.request("PROT P", 200) // encrypt data connection
	if err != nil {
		return err
	}

	return
}

// Noop verifies that the control connection is still responsive.
func (ftps *FTPS) Noop() error {
	_, err := ftps.request("NOOP", 200)
	return err
}

func (ftps *FTPS) request(cmd string, expected ...int) (message string, err error) {

	ftps.isConnEstablished()
	if strings.ContainsAny(cmd, "\r\n") {
		return "", errCommandContainsNewline
	}

	ftps.debugInfo("<*cmd*> " + redactCommand(cmd))

	clearDeadline, err := ftps.setDeadline(ftps.conn)
	if err != nil {
		return "", err
	}
	_, err = ftps.text.Cmd("%s", cmd)
	clearDeadline()
	if err != nil {
		return
	}

	message, err = ftps.response(expected...)

	return
}

func (ftps *FTPS) requestDataConn(cmd string, expected ...int) (dataConn net.Conn, err error) {

	port, err := ftps.pasv()
	if err != nil {
		return
	}

	dataConn, err = ftps.openDataConn(port)
	if err != nil {
		return nil, err
	}

	_, err = ftps.request(cmd, expected...)
	if err != nil {
		dataConn.Close()
		return nil, err
	}

	dataConn, err = ftps.upgradeConnToTLS(dataConn)
	if err != nil {
		return nil, err
	}

	return
}

func (ftps *FTPS) response(expected ...int) (message string, err error) {

	ftps.isConnEstablished()

	clearDeadline, err := ftps.setDeadline(ftps.conn)
	if err != nil {
		return "", err
	}
	defer clearDeadline()

	code, message, err := ftps.readResponse()

	ftps.debugInfo(fmt.Sprintf("<*code*> %d", code))
	ftps.debugInfo("<*message*> " + message)
	if err != nil {
		_ = ftps.conn.Close()
		return message, err
	}
	for _, expectedCode := range expected {
		if code == expectedCode {
			return message, nil
		}
	}

	return message, &textproto.Error{Code: code, Msg: message}
}

func (ftps *FTPS) upgradeConnToTLS(conn net.Conn) (net.Conn, error) {

	config := ftps.TLSConfig.Clone()
	if config.ServerName == "" {
		config.ServerName = ftps.host
	}
	tlsConn := tls.Client(conn, config)
	clearDeadline, err := ftps.setDeadline(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	defer clearDeadline()
	if err := tlsConn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (ftps *FTPS) pasv() (port int, err error) {

	message, err := ftps.request("PASV", 227)
	if err != nil {
		return 0, err
	}

	start := strings.Index(message, "(")
	end := strings.LastIndex(message, ")")

	if start == -1 || end == -1 {
		err = errors.New("Invalid PASV response format")
		return 0, err
	}

	pasvData := strings.Split(message[start+1:end], ",")
	if len(pasvData) != 6 {
		return 0, errors.New("invalid PASV response format")
	}

	portPart1, err := strconv.Atoi(pasvData[4])
	if err != nil {
		return 0, err
	}
	portPart2, err := strconv.Atoi(pasvData[5])
	if err != nil {
		return 0, err
	}
	if portPart1 < 0 || portPart1 > 255 || portPart2 < 0 || portPart2 > 255 {
		return 0, errors.New("invalid PASV port")
	}

	// Recompose port
	port = int(portPart1)*256 + int(portPart2)

	return
}

func (ftps *FTPS) PrintWorkingDirectory() (directory string, err error) {

	directory, err = ftps.request("PWD", 257)
	return
}

func (ftps *FTPS) ChangeWorkingDirectory(path string) (err error) {

	_, err = ftps.request(fmt.Sprintf("CWD %s", path), 250)
	return
}

func (ftps *FTPS) MakeDirectory(path string) (err error) {

	_, err = ftps.request(fmt.Sprintf("MKD %s", path), 257)
	return
}

func (ftps *FTPS) DeleteFile(path string) (err error) {

	_, err = ftps.request(fmt.Sprintf("DELE %s", path), 250)
	return
}

func (ftps *FTPS) RemoveDirectory(path string) (err error) {

	_, err = ftps.request(fmt.Sprintf("RMD %s", path), 250)
	return
}

func (ftps *FTPS) List() (entries []Entry, err error) {

	// TODO add support for MLSD

	dataConn, err := ftps.requestDataConn("LIST -a", 125, 150) // TODO use also -L to resolve links?
	if err != nil {
		return
	}
	defer dataConn.Close()

	clearDeadline, err := ftps.setDeadline(dataConn)
	if err != nil {
		return nil, err
	}
	defer clearDeadline()

	listLimit := configuredLimit(ftps.MaxListSize, DefaultMaxListSize)
	var reader io.Reader = dataConn
	var limited *io.LimitedReader
	if listLimit >= 0 {
		limited = &io.LimitedReader{R: dataConn, N: listLimit + 1}
		reader = limited
	}
	scanner := bufio.NewScanner(reader)
	maxLineSize := configuredIntLimit(ftps.MaxListLineSize, DefaultMaxListLineSize)
	initialBufferSize := min(4096, maxLineSize)
	scanner.Buffer(make([]byte, initialBufferSize), maxLineSize)
	var listErr error
	for scanner.Scan() {
		if limited != nil && limited.N == 0 {
			listErr = errListTooLarge
			break
		}
		entry, parseErr := ftps.parseEntryLine(scanner.Text())
		if parseErr != nil {
			listErr = parseErr
			break
		}
		entries = append(entries, *entry)
	}
	if listErr == nil {
		listErr = scanner.Err()
	}
	if listErr == nil && limited != nil && limited.N == 0 {
		listErr = errListTooLarge
	}
	if listErr != nil {
		ftps.discardDataAndFinish(dataConn)
		return nil, listErr
	}
	dataConn.Close()

	_, err = ftps.response(226)
	if err != nil {
		return
	}

	return
}

func (ftps *FTPS) parseEntryLine(line string) (entry *Entry, err error) {

	// TODO Function mostly copied from https://github.com/jlaffaye/ftp

	fields := strings.Fields(line)
	if len(fields) < 9 {
		return nil, errors.New("Unsupported line format.")
	}

	entry = &Entry{}

	// parse type
	switch fields[0][0] {
	case '-':
		entry.Type = EntryTypeFile
	case 'd':
		entry.Type = EntryTypeFolder
	case 'l':
		entry.Type = EntryTypeLink
	default:
		return nil, errors.New("Unknown entry type.")
	}

	// parse size
	size, err := strconv.ParseUint(fields[4], 10, 0)
	if err != nil {
		return nil, err
	}
	entry.Size = size

	// parse time
	var timeStr string
	if strings.Contains(fields[7], ":") { // this year
		thisYear, _, _ := time.Now().Date()
		timeStr = fmt.Sprintf("%s %s %d %s GMT", fields[6], fields[5], thisYear, fields[7])
	} else { // not this year
		timeStr = fmt.Sprintf("%s %s %s 00:00 GMT", fields[6], fields[5], fields[7])
	}
	t, err := time.Parse("_2 Jan 2006 15:04 MST", timeStr)
	if err != nil {
		return nil, err
	}
	entry.Time = t // TODO set timezone

	// parse name
	entry.Name = strings.Join(fields[8:], " ")

	return
}

func (ftps *FTPS) StoreFile(remoteFilepath string, data []byte) (err error) {
	return ftps.StoreReader(remoteFilepath, bytes.NewReader(data))
}

// StoreReader stores data read from r at remoteFilepath.
func (ftps *FTPS) StoreReader(remoteFilepath string, r io.Reader) (err error) {
	dataConn, err := ftps.requestDataConn(fmt.Sprintf("STOR %s", remoteFilepath), 125, 150)
	if err != nil {
		return
	}
	defer dataConn.Close()

	clearDeadline, err := ftps.setDeadline(dataConn)
	if err != nil {
		return err
	}
	defer clearDeadline()
	_, err = io.Copy(dataConn, r)
	if err != nil {
		return
	}
	if err = dataConn.Close(); err != nil {
		return
	}

	_, err = ftps.response(226)

	return
}

func (ftps *FTPS) RetrieveFileData(remoteFilepath string) (data []byte, err error) {

	dataConn, err := ftps.requestDataConn(fmt.Sprintf("RETR %s", remoteFilepath), 125, 150)
	if err != nil {
		return
	}
	defer dataConn.Close()

	buf := new(bytes.Buffer)

	clearDeadline, err := ftps.setDeadline(dataConn)
	if err != nil {
		return nil, err
	}
	defer clearDeadline()
	retrieveLimit := configuredLimit(ftps.MaxRetrieveSize, DefaultMaxRetrieveSize)
	var reader io.Reader = dataConn
	if retrieveLimit >= 0 {
		reader = io.LimitReader(dataConn, retrieveLimit+1)
	}
	n, err := buf.ReadFrom(reader)
	if err != nil {
		return
	}
	if retrieveLimit >= 0 && n > retrieveLimit {
		ftps.discardDataAndFinish(dataConn)
		return nil, errRetrieveTooLarge
	}

	data = buf.Bytes()

	err = dataConn.Close()
	if err != nil {
		return
	}

	_, err = ftps.response(226)
	if err != nil {
		return
	}

	return
}

func (ftps *FTPS) RetrieveFile(remoteFilepath, localFilepath string) (err error) {
	file, err := os.Create(localFilepath)
	if err != nil {
		return err
	}
	defer file.Close()

	return ftps.RetrieveWriter(remoteFilepath, file)
}

// RetrieveWriter retrieves remoteFilepath and writes its contents to w.
func (ftps *FTPS) RetrieveWriter(remoteFilepath string, w io.Writer) (err error) {
	dataConn, err := ftps.requestDataConn(fmt.Sprintf("RETR %s", remoteFilepath), 125, 150)
	if err != nil {
		return
	}
	defer dataConn.Close()

	clearDeadline, err := ftps.setDeadline(dataConn)
	if err != nil {
		return err
	}
	defer clearDeadline()
	_, err = io.Copy(w, dataConn)
	if err != nil {
		return
	}
	if err = dataConn.Close(); err != nil {
		return
	}

	_, err = ftps.response(226)
	if err != nil {
		return
	}

	return
}

func (ftps *FTPS) Quit() (err error) {

	_, err = ftps.request("QUIT", 221)
	if err != nil {
		return
	}
	ftps.conn.Close()

	return
}

func (ftps *FTPS) openDataConn(port int) (dataConn net.Conn, err error) {

	host := ftps.dataHost
	if host == "" {
		host = ftps.host
	}
	dataConn, err = ftps.dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return
	}

	return
}

func (ftps *FTPS) dial(network, address string) (net.Conn, error) {
	if ftps.Dialer != nil {
		if dialer, ok := ftps.Dialer.(interface {
			DialContext(context.Context, string, string) (net.Conn, error)
		}); ok && ftps.timeout() > 0 {
			ctx, cancel := context.WithTimeout(context.Background(), ftps.timeout())
			defer cancel()
			return dialer.DialContext(ctx, network, address)
		}
		return ftps.Dialer.Dial(network, address)
	}
	if ftps.timeout() <= 0 {
		return net.Dial(network, address)
	}
	return net.DialTimeout(network, address, ftps.timeout())
}

func (ftps *FTPS) readResponse() (code int, message string, err error) {
	limit := configuredLimit(ftps.MaxControlResponseSize, DefaultMaxControlResponseSize)
	remaining := limit
	line, err := ftps.readResponseLine(&remaining)
	if err != nil {
		return 0, "", err
	}
	code, continued, first, err := parseResponseLine(line)
	if err != nil {
		return 0, "", err
	}

	var messageBuilder strings.Builder
	messageBuilder.WriteString(first)
	for continued {
		line, err = ftps.readResponseLine(&remaining)
		if err != nil {
			return 0, "", err
		}
		messageBuilder.WriteByte('\n')
		lineCode, lineContinued, lineMessage, parseErr := parseResponseLine(line)
		if parseErr == nil && lineCode == code {
			messageBuilder.WriteString(lineMessage)
			continued = lineContinued
			continue
		}
		messageBuilder.WriteString(line)
	}
	return code, messageBuilder.String(), nil
}

func (ftps *FTPS) discardDataAndFinish(dataConn net.Conn) {
	if _, err := io.Copy(io.Discard, dataConn); err != nil {
		_ = ftps.conn.Close()
		return
	}
	if err := dataConn.Close(); err != nil {
		_ = ftps.conn.Close()
		return
	}
	if _, err := ftps.response(226); err != nil {
		_ = ftps.conn.Close()
	}
}

func (ftps *FTPS) readResponseLine(remaining *int64) (string, error) {
	var line []byte
	for {
		fragment, err := ftps.text.Reader.R.ReadSlice('\n')
		if *remaining >= 0 {
			if int64(len(fragment)) > *remaining {
				return "", errResponseTooLarge
			}
			*remaining -= int64(len(fragment))
		}
		line = append(line, fragment...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			return "", err
		}
		line = bytes.TrimSuffix(line, []byte{'\n'})
		line = bytes.TrimSuffix(line, []byte{'\r'})
		return string(line), nil
	}
}

func parseResponseLine(line string) (code int, continued bool, message string, err error) {
	if len(line) < 4 || line[3] != ' ' && line[3] != '-' {
		return 0, false, "", textproto.ProtocolError(fmt.Sprintf("short response: %q", line))
	}
	code, err = strconv.Atoi(line[:3])
	if err != nil || code < 100 {
		return 0, false, "", textproto.ProtocolError(fmt.Sprintf("invalid response code: %q", line))
	}
	return code, line[3] == '-', line[4:], nil
}

func (ftps *FTPS) setDeadline(conn net.Conn) (func(), error) {
	timeout := ftps.timeout()
	if timeout <= 0 {
		return func() {}, nil
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	return func() { _ = conn.SetDeadline(time.Time{}) }, nil
}

func (ftps *FTPS) timeout() time.Duration {
	if ftps.Timeout == 0 {
		return DefaultTimeout
	}
	return ftps.Timeout
}

func configuredLimit(value, defaultValue int64) int64 {
	if value == 0 {
		return defaultValue
	}
	return value
}

func configuredIntLimit(value, defaultValue int) int {
	if value == 0 {
		return defaultValue
	}
	if value < 0 {
		return int(^uint(0) >> 1)
	}
	return value
}

func redactCommand(cmd string) string {
	if strings.HasPrefix(cmd, "PASS ") {
		return "PASS <redacted>"
	}
	return cmd
}

func (ftps *FTPS) debugInfo(message string) {

	if ftps.Debug {
		log.Println(message)
	}
}
