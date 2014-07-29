package ftps

import (
	"io/ioutil"
	"log"
	"testing"
)

func TestFTPS(t *testing.T) {

	ftps := new(FTPS)

	ftps.TLSConfig.InsecureSkipVerify = true
	ftps.Debug = false

	err := ftps.Connect("localhost", 21)
	if err != nil {
		panic(err)
	}

	err = ftps.Login("ftptester", "ftptester")
	if err != nil {
		panic(err)
	}

	directory, err := ftps.PrintWorkingDirectory()
	if err != nil {
		panic(err)
	}
	log.Printf("Current working directory: %s", directory)

	err = ftps.MakeDirectory("websites")
	if err != nil {
		panic(err)
	}

	err = ftps.ChangeWorkingDirectory("websites")
	if err != nil {
		panic(err)
	}

	directory, err = ftps.PrintWorkingDirectory()
	if err != nil {
		panic(err)
	}
	log.Printf("Current working directory: %s", directory)

	err = ftps.ChangeWorkingDirectory("..")
	if err != nil {
		panic(err)
	}

	directory, err = ftps.PrintWorkingDirectory()
	if err != nil {
		panic(err)
	}
	log.Printf("Current working directory: %s", directory)

	err = ftps.RemoveDirectory("websites")
	if err != nil {
		panic(err)
	}

	directory, err = ftps.PrintWorkingDirectory()
	if err != nil {
		panic(err)
	}
	log.Printf("Current working directory: %s", directory)

	data, err := ioutil.ReadFile("ftps.go")
	if err != nil {
		panic(err)
	}
	err = ftps.StoreFile("test.go", data)
	if err != nil {
		panic(err)
	}

	// TODO test deleteFile

	//ftps.List() // TODO error handlin

	err = ftps.Quit()
	if err != nil {
		panic(err)
	}
}
