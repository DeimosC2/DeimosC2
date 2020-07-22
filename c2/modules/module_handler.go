package modules

import (
	"container/list"
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
	"runtime"
	"strconv"
	"sync"

	"github.com/DeimosC2/DeimosC2/c2/loot"
	"github.com/DeimosC2/DeimosC2/c2/webserver/websockets"
	"github.com/DeimosC2/DeimosC2/lib/logging"
	"github.com/DeimosC2/DeimosC2/lib/modulescommon"
)

//ModData is used for RPC
type ModData int

var queue = list.New()

var rpcPort = 63001

//The point of this file is to pass data from listeners into the appropiate modules

//AllModules is a varibales to store the modules in
var AllModules = &Modules{mutex: sync.RWMutex{}, List: map[string]*Module{}}

//Modules holds a list of modules that have data coming to them
type Modules struct {
	mutex sync.RWMutex
	List  map[string]*Module
}

//Module is a struct for the module to be identified by
type Module struct {
	Name string //Holds the name of the module
	Port int    //Holds the RPC port of the module server
}

//AgentPair is used for the queue of agents that need to be paired with the correct module
type AgentPair struct {
	AgentKey   string //Name of the agent
	ModuleName string //Name of the module requested
}

//StartModuleServer will start up the RPC server required for module communication
//This will only be called from main when the server starts up initially
func StartModuleServer() {
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

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}

		go rpc.ServeCodec(jsonrpc.NewServerCodec(conn))
	}

}

//StartModule will start a module up and set the data to be sent to it
func StartModule(data modulescommon.ModuleCom, ft string) {
	logging.Logger.Println("Starting module " + data.ModuleName)
	cwd, err := os.Getwd()
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	s := strconv.Itoa(rpcPort)

	logging.Logger.Println("Server filetpye is: " + ft)
	//FT should be whatever the server is running, not what the agent is running.
	switch runtime.GOOS {
	case "windows":
		ft = ".exe"
	case "linux":
		ft = ".elf"
	case "darwin":
		ft = ".o"
	}

	cmd := exec.Command(path.Join(cwd, "modules", data.ModuleType, data.ModuleName, "server", "bin", data.ModuleName+ft), s)
	logging.Logger.Println(cmd)
	cmd.Start()

}

//ModInit -> Called when a module first spins up and we send the first bit of data expected to them
func (t *ModData) ModInit(m Module, reply *[]byte) error {
	logging.Logger.Println("Module " + m.Name + " has checked in")
	logging.Logger.Println(m)
	AllModules.mutex.Lock()
	defer AllModules.mutex.Unlock()

	//Go through the queue to see who asked for this module
	if queue.Len() > 0 {
		e := queue.Front() // First element
		fmt.Print(e.Value)
		logging.Logger.Println(e)
		logging.Logger.Println(e.Value.(AgentPair).ModuleName)
		i := 0

		if e.Value.(AgentPair).ModuleName == m.Name {
			AllModules.List[e.Value.(AgentPair).AgentKey] = &m
			queue.Remove(e)
			logging.Logger.Println(AllModules)
			return nil
		}

		for queue.Len() > i {
			e = e.Next()
			i++
			if e.Value.(AgentPair).ModuleName == m.Name {
				AllModules.List[e.Value.(AgentPair).AgentKey] = &m
				queue.Remove(e)
				logging.Logger.Println(AllModules)
				return nil
			}
			i++
		}
	}
	return nil
}

//ModSendData -> Called when a module needs to send data back to the main server
func (t *ModData) ModSendData(m modulescommon.ModOutput, reply *[]byte) error {
	logging.Logger.Println("SendData called")
	logging.Logger.Println(m)
	//Send Loot data for it to be processed
	if m.OutputType == "Loot" {
		loot.SaveLoot(m.AgentKey, m.Output)
	}
	jsonM, _ := json.Marshal(m)
	outMsg := websockets.SendMessage{
		Type:         "Agent",
		FunctionName: "ModOutput",
		Data:         string(jsonM),
		Success:      true,
	}
	websockets.AlertRegisteredUsers(outMsg, m.AgentKey)
	logging.Logger.Println("End of ModSendData")
	return nil
}

//ModuleServer takes in the data being passed to modules and passes it to where it needs to go
//At this point the server should have already been registered and be waiting for some sort of input from the main binary
func ModuleServer(data modulescommon.ModuleCom) {
	logging.Logger.Println("Modules called to give data to the modserver")
	AllModules.mutex.Lock()
	defer AllModules.mutex.Unlock()
	logging.Logger.Println(AllModules.List[data.AgentKey])

	s := strconv.Itoa(AllModules.List[data.AgentKey].Port)
	//This is here for debugging assistance
	//s := "63002"
	conn, err := net.Dial("tcp", "127.0.0.1:"+s)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	defer conn.Close()

	client := jsonrpc.NewClient(conn)

	logging.Logger.Println(data.AgentKey)
	logging.Logger.Println(data.Kill)

	if data.Kill == true {
		var reply bool
		err = client.Call("ModData.EndServer", data.Kill, &reply)
		if err != nil {
			logging.ErrorLogger.Println("RPC Error: ", err.Error())
		}
	} else {
		reply := ""
		err = client.Call("ModData.RecData", data, &reply)
		if err != nil {
			logging.ErrorLogger.Println("RPC Error: ", err.Error())
		}
		if reply != "" {
			//Reply format should be a string if there is anything in the string then send it the the front end. else just move on.
			logging.Logger.Println(reply)
			outMsg := websockets.SendMessage{
				Type:         "Agent",
				FunctionName: "ModOutput",
				Data:         reply,
				Success:      true,
			}
			websockets.AlertRegisteredUsers(outMsg, data.AgentKey)
		}
	}
}

//SendModule will take in the name and type of the module and return the binary data
//Module will be precompiled
//THIS NEEDS TO BE CHANGED
func SendModule(data modulescommon.ModuleCom) string {
	logging.Logger.Println("Sending Module...")
	logging.Logger.Println(data)
	cwd, err := os.Getwd()
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	//Generate the agent pair and add it to the queue
	logging.Logger.Println("AGENT PAIR: " + data.AgentKey + " : " + data.ModuleName)
	ap := AgentPair{data.AgentKey, data.ModuleName}
	queue.PushBack(ap)
	logging.Logger.Println(queue)

	//Now start the module then return the binary
	StartModule(data, data.FileType)

	location := path.Join(cwd, "modules", data.ModuleType, data.ModuleName, "agents", "bin", data.ModuleName+data.FileType)

	logging.Logger.Println(data.FileType)
	var binary []byte
	if data.FileType == ".dll" {
		var args []string
		//TODO Take these from the frontend chase
		args = append(args, "1234")
		binary, _ = Parse(location, args)
	} else {
		logging.Logger.Println("location is:", location)
		binary, err = ioutil.ReadFile(location)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
			return "Failed to find binary"
		}
	}

	return base64.StdEncoding.EncodeToString(binary)
}
