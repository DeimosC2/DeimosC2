package websockets

import (
	"sync"

	"github.com/gorilla/websocket"
)

//SendMessage defines the structure of the message to the frontend
type SendMessage struct {
	Type         string //Type of message to send to the front end
	FunctionName string //Holds the function names
	Data         string //data to be sent
	Success      bool   //If it succeed or not
}

//AllClients that are currently connected
var AllClients = &Clients{Mutex: sync.RWMutex{}, List: make(map[*websocket.Conn]*Client)}

//RShellClients holds the channel for each RShell
var RShellClients = &RShellClient{Mutex: sync.RWMutex{}, Channel: make(map[string]chan string)}

//Clients is a struct for syncing client operations
type Clients struct {
	Mutex sync.RWMutex
	List  map[*websocket.Conn]*Client
}

//Client is a struct holding data the clients are interested in
type Client struct {
	Agents []string
	Alive  bool
}

//RShellClient hows the structure of Reverse Shell Clients
type RShellClient struct {
	Mutex   sync.RWMutex
	Channel map[string]chan string
}

//AlertUsers will send data to all front end users that needs to be known.
//Data can include listeners being spun up, agents connecting etc..
//Message is expected to already be formatted when set
func AlertUsers(m SendMessage) {
	AllClients.Mutex.Lock()
	defer AllClients.Mutex.Unlock()
	for k, v := range AllClients.List {
		if v.Alive == true {
			k.WriteJSON(m)
		}

	}
}

//AlertSingleUser sends data back to a single user
func AlertSingleUser(m SendMessage, ws *websocket.Conn) {
	AllClients.Mutex.Lock()
	defer AllClients.Mutex.Unlock()
	ws.WriteJSON(m)
}

//AlertRegisteredUsers sends data onto the the interested users
func AlertRegisteredUsers(m SendMessage, name string) {
	AllClients.Mutex.Lock()
	defer AllClients.Mutex.Unlock()
	for k, v := range AllClients.List {
		if v.Alive == true {
			for _, n := range v.Agents {
				if n == name {
					k.WriteJSON(m)
				}
			}
		}
	}
}

//RegisterAgent registers an agent for the webserver to send data back too
func RegisterAgent(ws *websocket.Conn, name string) {
	AllClients.Mutex.Lock()
	defer AllClients.Mutex.Unlock()
	AllClients.List[ws].Agents = append(AllClients.List[ws].Agents, name)
}

//DeregisterAgent removes the agent from the defined clients interested list
func DeregisterAgent(ws *websocket.Conn, name string) {
	AllClients.Mutex.Lock()
	defer AllClients.Mutex.Unlock()

	for i, v := range AllClients.List[ws].Agents {
		if v == name {
			AllClients.List[ws].Agents = append(AllClients.List[ws].Agents[:i], AllClients.List[ws].Agents[i+1:]...)
		}
	}
}
