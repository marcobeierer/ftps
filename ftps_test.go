package ftps

import (
	"testing"
	//"fmt"
	//"os"
)

func TestFTPS(t *testing.T) {

	ftps := new(FTPS)

	ftps.TLSConfig.InsecureSkipVerify = true
	ftps.Debug = true

	ftps.Connect("localhost", 21)
	ftps.Login("ftptester", "ftptester")
	ftps.PrintWorkingDirectory()
	ftps.ChangeWorkingDirectory("websites")
	ftps.PrintWorkingDirectory()
	ftps.MakeDirectory("websites")
	ftps.List()
	ftps.Quit()
}
