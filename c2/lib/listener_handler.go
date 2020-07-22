package lib

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/AdvancedThreatAnalytics/DeimosC2/c2/agents"
	"github.com/AdvancedThreatAnalytics/DeimosC2/c2/webserver/websockets"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/miekg/dns"

	"github.com/AdvancedThreatAnalytics/DeimosC2/c2/lib/gobuild"
	"github.com/AdvancedThreatAnalytics/DeimosC2/c2/lib/sqldb"
	"github.com/AdvancedThreatAnalytics/DeimosC2/c2/lib/validation"
	"github.com/AdvancedThreatAnalytics/DeimosC2/c2/listeners"
	"github.com/AdvancedThreatAnalytics/DeimosC2/lib/crypto"
	"github.com/AdvancedThreatAnalytics/DeimosC2/lib/logging"
	"github.com/gorilla/websocket"

	uuid "github.com/satori/go.uuid"
)

//AllListeners is a global variable that holds all the listeners
var AllListeners = &MListeners{mutex: sync.RWMutex{}, list: map[string]*Listener{}}

//MListeners is the struct for a list of all listeners
type MListeners struct {
	mutex sync.RWMutex
	list  map[string]*Listener
}

//Listener struct holds data on all listeners
type Listener struct {
	LType        string      //Type of listener
	Name         string      //Listener name
	Host         string      //IP or FQDN of the server
	Port         string      //Port to listen on
	ListChan     chan bool   //Channel used to kill off the listeners
	Key          string      //Listener UUID4 name
	PrivKey      []byte      //RSA private key
	PubKey       []byte      //RSA public key
	Advanced     interface{} //Advanced listener options held as JSON here
	AgentOptions listeners.AgentOptions
}

//StartNewListener will start up a new listener of the type and options that are expected
func StartNewListener(newListener listeners.ListOptions, userID string, editing bool, gooses []string, obfuscation bool, username string) (bool, *Listener) {

	AllListeners.mutex.Lock()
	defer AllListeners.mutex.Unlock()

	var lName string
	if newListener.LType != "PIVOTTCP" && !editing {
		lName = uuid.NewV4().String()
	} else {
		lName = newListener.Key
	}

	//Get RSA Private and Public Keys
	priv, pub := crypto.GenerateKeyPair(2048)
	//Convert keys to bytes and store in the listener struct

	newListener.Key = lName

	newL := &Listener{
		LType:        newListener.LType,
		Name:         newListener.Name,
		Host:         newListener.Host,
		Port:         newListener.Port,
		ListChan:     make(chan bool),
		Key:          lName,
		PrivKey:      crypto.PrivateKeyToBytes(priv), //Generates the privkey
		PubKey:       crypto.PublicKeyToBytes(pub),   //Generates the PubKey
		Advanced:     newListener.Advanced,
		AgentOptions: newListener.AgentOptions,
	}

	//DoH uses an AES key instead so the other keys are overwritte here in order to use the same struct
	if newL.LType == "DoH" {
		newL.PubKey = make([]byte, 32)
		_, _ = rand.Read(newL.PubKey)
		newL.PrivKey = newL.PubKey
	}

	//Could make this a pointer instead of just copying it back over.... that would be a better way add to refactor part 2
	success := startListener(newL, userID, username)

	if success {
		adv, _ := json.Marshal(newL.Advanced)

		if editing {
			sqldb.EditListener(newL.Key, newL.Name, newL.LType, newL.Host, newL.Port, newL.PubKey, newL.PrivKey, string(adv), newL.AgentOptions.Delay, newL.AgentOptions.Jitter, newL.AgentOptions.Eol, newL.AgentOptions.LiveHours, userID)
		} else {
			sqldb.AddListener(newL.Key, newL.Name, newL.LType, newL.Host, newL.Port, newL.PubKey, newL.PrivKey, string(adv), newL.AgentOptions.Delay, newL.AgentOptions.Jitter, newL.AgentOptions.Eol, newL.AgentOptions.LiveHours, userID)

		}

		//Here we need to start generating the binaries
		//Default means it just takes in the users data nothing more
		go gobuild.Init(newL.LType, newL.Key, newL.PubKey, newL.Host, newL.Port, newL.AgentOptions.Delay, newL.AgentOptions.Jitter, newL.AgentOptions.Eol, newL.AgentOptions.LiveHours, newL.Advanced, gooses, []string{"386", "amd64"}, obfuscation)
	}
	return success, newL
}

//Takes in the listener object, makes sure it doesnt already exists, if so then it starts the listener and adds it to the mask
func startListener(l *Listener, userID string, username string) bool {
	var success bool
	var tcpL net.Listener
	var httpsL *http.Server
	var DNSL *dns.Server
	var QuicL *http3.Server
	if _, ok := AllListeners.list[l.Key]; ok {
		logging.ErrorLogger.Println("key for this listener already exists")
		return false //, Listener{}
	}

	newListener := listeners.ListOptions{
		LType:        l.LType,
		Name:         l.Name,
		Host:         l.Host,
		Port:         l.Port,
		Key:          l.Key,
		Advanced:     l.Advanced,
		AgentOptions: l.AgentOptions,
	}

	switch l.LType {
	case "TCP":
		tcpL, success = listeners.StartTCPServer(newListener, l.PrivKey)
		go killNetList(tcpL, l)
	case "HTTPS":
		httpsL, success = listeners.StartHTTPSServer(newListener, l.PrivKey, l.PubKey)
		go killHTTPSList(httpsL, l)
	case "DoH":
		success, DNSL = listeners.StartDNSHTTPSServer(newListener, l.PrivKey)
		go killDNSList(DNSL, l)
	case "PIVOTTCP":
		//make sure the agent exists, send the job down to the agent, when the job is successful return here.
		success = agents.PivotListener(newListener.Key, l.PrivKey, l.Port, userID, username)
		go killPivotTCPList(l, userID, username)
	case "QUIC":
		QuicL, success = listeners.StartQUICServer(newListener, l.PrivKey, l.PubKey)
		go killQUICList(QuicL, l)
	}
	if success {
		AllListeners.list[l.Key] = l
	}
	return success
}

//ReInitListener rebuilds the live listeners from the database
func ReInitListener(l Listener) {
	l.ListChan = make(chan bool)

	startListener(&l, "Server Restarted", "")
}

//stopListener will stop the listener that is passed to it
func stopListener(key string) {

	AllListeners.mutex.Lock()
	defer AllListeners.mutex.Unlock()
	if val, ok := AllListeners.list[key]; ok {
		val.ListChan <- true
		delete(AllListeners.list, key)
	}

	sqldb.RemoveListener(key)
}

func killNetList(l net.Listener, c *Listener) {
	<-c.ListChan
	logging.Logger.Println("Murdering the listener up")
	l.Close()
}

func killHTTPSList(l *http.Server, c *Listener) {
	<-c.ListChan
	logging.Logger.Println("Murdering the listener up")
	l.Shutdown(context.TODO())
}

func killQUICList(l *http3.Server, c *Listener) {
	<-c.ListChan
	logging.Logger.Println("Murdering the listener up")
	l.Shutdown(context.TODO())
}

func killDNSList(l *dns.Server, c *Listener) {
	<-c.ListChan
	logging.Logger.Println("Murdering the listener up")
	l.Shutdown()
}

func killPivotTCPList(c *Listener, userID string, username string) {
	<-c.ListChan
	logging.Logger.Println("Murdering the listener up")
	listenerKillJob := agents.AgentJob{
		AgentKey:  c.Key,
		JobType:   "pivotKill",
		Arguments: []string{},
	}
	agents.SetJob(listenerKillJob, userID, username)
}

//getCompiled returns a list of compiled binaries
func getCompiled(key string) (bool, []string) {
	//Arrays to store the file and directory info
	var binFiles []string

	//Current directory
	cwd, err := os.Getwd()
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	//Full path of the looted directory
	listenerPath := filepath.Join(cwd, "resources", "listenerresources", key)

	//Check to ensure path meets valid characters
	var validName = regexp.MustCompile(`[^a-zA-Z0-9-\/]+`)
	if validName.MatchString(key) == false {
		files, _ := ioutil.ReadDir(listenerPath)

		for _, file := range files {
			binFiles = append(binFiles, "listenerresources/"+key+"/"+file.Name())
		}
	}
	return true, binFiles
}

//ParseSocket takes in data from the websocket and does what it needs to with it
func ParseSocket(fname string, data interface{}, ws *websocket.Conn, userID string, username string) {
	m := data.(map[string]interface{})

	if fname == "List" {
		AllListeners.mutex.Lock()
		defer AllListeners.mutex.Unlock()
		msg := "["
		for _, v := range AllListeners.list {
			l := listeners.ListOptions{
				LType:        v.LType,
				Name:         v.Name,
				Host:         v.Host,
				Port:         v.Port,
				Key:          v.Key,
				Advanced:     v.Advanced,
				AgentOptions: v.AgentOptions,
			}
			newMsg, _ := json.Marshal(l)
			msg += string(newMsg) + ","
		}
		msg = strings.TrimSuffix(msg, ",")
		msg += "]"
		outMsg := websockets.SendMessage{
			Type:         "Listener",
			FunctionName: "List",
			Data:         msg,
			Success:      true,
		}
		websockets.AlertSingleUser(outMsg, ws)
		return

	} else if fname == "Kill" {
		if !validation.ValidateMapAlert(m, []string{"Key"}, ws) {
			return
		}

		stopListener(m["Key"].(string))
		name := "{\"Name\": \"" + m["Key"].(string) + "\"}"
		outMsg := websockets.SendMessage{
			Type:         "Listener",
			FunctionName: "Kill",
			Data:         name,
			Success:      true,
		}
		websockets.AlertUsers(outMsg)
		return

	} else if fname == "CreateAgent" {
		if !validation.ValidateMapAlert(m, []string{"Key", "Obfuscate", "Arch", "OS"}, ws) {
			return
		}
		var gooses []string
		switch val := m["OS"].(type) {
		case []interface{}:
			for _, x := range val {
				gooses = append(gooses, x.(string))
			}
		}
		var arches []string
		switch val := m["Arch"].(type) {
		case []interface{}:
			for _, x := range val {
				arches = append(arches, x.(string))
			}
		}
		//get the data needed from the map
		AllListeners.mutex.Lock()
		if val, ok := AllListeners.list[m["Key"].(string)]; ok {
			gobuild.Init(val.LType, val.Key, val.PubKey, val.Host, val.Port, val.AgentOptions.Delay, val.AgentOptions.Jitter, val.AgentOptions.Eol, val.AgentOptions.LiveHours, val.Advanced, gooses, arches, m["Obfuscate"].(bool))
		}

		AllListeners.mutex.Unlock()
		return
	} else if fname == "GetListenerPrivateKey" {
		if !validation.ValidateMapAlert(m, []string{"Key"}, ws) {
			return
		}

		msg := make(map[string]string)
		msg["PrivateKey"] = sqldb.GetListenerPrivateKey(m["Key"].(string))
		sendMsg, _ := json.Marshal(msg)
		outMsg := websockets.SendMessage{
			Type:         "Listener",
			FunctionName: "GetListenerPrivateKey",
			Data:         string(sendMsg),
			Success:      true,
		}

		websockets.AlertSingleUser(outMsg, ws)
		return

	} else if fname == "GetCompiled" {
		if !validation.ValidateMapAlert(m, []string{"Key"}, ws) {
			return
		}

		success, files := getCompiled(m["Key"].(string))

		msg, _ := json.Marshal(files)

		outMsg := websockets.SendMessage{
			Type:         "Listener",
			FunctionName: "GetCompiled",
			Data:         string(msg),
			Success:      success,
		}

		websockets.AlertSingleUser(outMsg, ws)
		return
	}

	if !validation.ValidateMapAlert(m, []string{"LType", "Name", "Host", "Port", "Key", "Advanced", "CompileOptions"}, ws) {
		return
	}

	cOptions := m["CompileOptions"].(map[string]interface{})

	var gooses []string

	var obfuscation bool

	for x, y := range cOptions {

		if x == "Obfuscated" {
			obfuscation = y.(bool)
		} else {
			if y.(bool) {
				gooses = append(gooses, strings.ToLower(x))
			}
		}

	}

	ao := m["AgentOptions"].(map[string]interface{})

	if !validation.ValidateMapAlert(ao, []string{"Delay", "Eol", "Jitter", "LiveHours"}, ws) {
		return
	}

	listener := listeners.ListOptions{
		LType:    strings.TrimSpace(m["LType"].(string)),
		Name:     strings.TrimSpace(m["Name"].(string)),
		Host:     strings.TrimSpace(m["Host"].(string)),
		Port:     strings.TrimSpace(m["Port"].(string)),
		Key:      strings.TrimSpace(m["Key"].(string)),
		Advanced: m["Advanced"],
		AgentOptions: listeners.AgentOptions{
			Delay:     strings.TrimSpace(ao["Delay"].(string)),
			Eol:       strings.TrimSpace(ao["Eol"].(string)),
			Jitter:    strings.TrimSpace(ao["Jitter"].(string)),
			LiveHours: strings.TrimSpace(ao["LiveHours"].(string)),
		},
	}

	if fname == "Add" {
		success, newL := StartNewListener(listener, userID, false, gooses, obfuscation, username)

		l := listeners.ListOptions{
			LType:        newL.LType,
			Name:         newL.Name,
			Host:         newL.Host,
			Port:         newL.Port,
			Key:          newL.Key,
			Advanced:     newL.Advanced,
			AgentOptions: newL.AgentOptions,
		}
		newMsg, _ := json.Marshal(l)
		outMsg := websockets.SendMessage{
			Type:         "Listener",
			FunctionName: "Add",
			Data:         string(newMsg),
			Success:      success,
		}
		websockets.AlertUsers(outMsg)

	} else if fname == "Edit" {
		stopListener(listener.Key)
		success, newL := StartNewListener(listener, userID, true, gooses, obfuscation, username)

		l := listeners.ListOptions{
			LType:        newL.LType,
			Name:         newL.Name,
			Host:         newL.Host,
			Port:         newL.Port,
			Key:          newL.Key,
			Advanced:     newL.Advanced,
			AgentOptions: newL.AgentOptions,
		}
		newMsg, _ := json.Marshal(l)
		outMsg := websockets.SendMessage{
			Type:         "Listener",
			FunctionName: "Edit",
			Data:         string(newMsg),
			Success:      success,
		}
		websockets.AlertUsers(outMsg)

	} else {
		logging.Logger.Println("Pass a real option.")
	}
}
