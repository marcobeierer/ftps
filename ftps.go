// http://stackoverflow.com/questions/13110713/upgrade-a-connection-to-tls-in-go
// https://github.com/jlaffaye/ftp/blob/master/ftp.go

// TODO redefine error handling
// TODO handle error if certificate could not be verified
// TODO test, ob wirklich verschluesselt

// TODO change command names (z.B. Cwd to ChangeWorkingDirectory)

// TODO remove debug stuff

package ftps

import (
	"bufio"
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
)

type FTPS struct {
	host string

	conn net.Conn
	text *textproto.Conn

	Debug     bool
	TLSConfig tls.Config
}

func (ftps *FTPS) Connect(host string, port int) (err error) {

	ftps.host = host

	ftps.conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return err
	}

	ftps.text = textproto.NewConn(ftps.conn)

	//_, message, err := ftps.text.ReadResponse(220)
	//ftps.debugInfo(message)
	_, err = ftps.response(220)
	if err != nil {
		return err
	}

	_, err = ftps.request("AUTH TLS", 234)
	if err != nil {
		return err
	}

	ftps.conn = ftps.upgradeConnToTLS(ftps.conn)
	ftps.text = textproto.NewConn(ftps.conn) // TODO use sync or something similar?

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

func (ftps *FTPS) request(cmd string, expected int) (message string, err error) {

	ftps.isConnEstablished()

	ftps.debugInfo("<*cmd*> " + cmd)

	_, err = ftps.text.Cmd(cmd)
	if err != nil {
		return
	}

	message, err = ftps.response(expected)

	return
}

func (ftps *FTPS) requestDataConn(cmd string, expected int) (dataConn net.Conn, err error) {

	port, err := ftps.pasv()
	if err != nil {
		return
	}

	dataConn, err = ftps.openDataConn(port)
	if err != nil {
		return nil, err
	}

	_, err = ftps.request(cmd, expected)
	if err != nil {
		dataConn.Close()
		return nil, err
	}

	dataConn = ftps.upgradeConnToTLS(dataConn)

	return
}

func (ftps *FTPS) response(expected int) (message string, err error) {

	ftps.isConnEstablished()

	code, message, err := ftps.text.ReadResponse(expected)

	ftps.debugInfo(fmt.Sprintf("<*code*> %d", code))
	ftps.debugInfo("<*message*> " + message)

	return
}

func (ftps *FTPS) upgradeConnToTLS(conn net.Conn) (upgradedConn net.Conn) {

	var tlsConn *tls.Conn
	tlsConn = tls.Client(conn, &ftps.TLSConfig)

	tlsConn.Handshake()
	upgradedConn = net.Conn(tlsConn)

	// TODO verify that TLS connection is established

	return
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

	portPart1, err := strconv.Atoi(pasvData[4])
	if err != nil {
		return 0, err
	}

	portPart2, err := strconv.Atoi(pasvData[5])
	if err != nil {
		return 0, err
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

func (ftps *FTPS) List() (err error) { // TODO return entries slice and error

	dataConn, err := ftps.requestDataConn("LIST", 150)
	if err != nil {
		return
	}
	defer dataConn.Close()

	reader := bufio.NewReader(dataConn)
	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		fmt.Print(line)
	}

	return
}

func (ftps *FTPS) StoreFile(remoteFilepath string, data []byte) (err error) {

	dataConn, err := ftps.requestDataConn(fmt.Sprintf("STOR %s", remoteFilepath), 150)
	if err != nil {
		return
	}
	defer dataConn.Close()

	count, err := dataConn.Write(data)
	if err != nil {
		return
	}
	dataConn.Close()

	if len(data) != count {
		return errors.New("File transfer not complete.")
	}

	_, err = ftps.response(226)
	if err != nil {
		return
	}

	return
}

func (ftps *FTPS) RetrieveFile(remoteFilepath, localFilepath string) (err error) {

	dataConn, err := ftps.requestDataConn(fmt.Sprintf("RETR %s", remoteFilepath), 150)
	if err != nil {
		return
	}
	defer dataConn.Close()

	file, err := os.Open(localFilepath)
	if err != nil {
		return
	}

	_, err = io.Copy(file, dataConn)
	if err != nil {
		return
	}
	dataConn.Close()

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

	dataConn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", ftps.host, port))
	if err != nil {
		return
	}

	return
}

func (ftps *FTPS) debugInfo(message string) {

	if ftps.Debug {
		log.Println(message)
	}
}
