package webserver

import (
	"encoding/json"
	"strings"

	"github.com/DeimosC2/DeimosC2/c2/lib/sqldb"
	"github.com/DeimosC2/DeimosC2/c2/lib/validation"
	"github.com/DeimosC2/DeimosC2/c2/webserver/websockets"
	"github.com/DeimosC2/DeimosC2/lib/logging"
	"github.com/gorilla/websocket"
)

//PivotGraph struct holds data for the API call
type PivotGraph struct {
	Listenerkey string       `json:"listenerkey"`
	Name        string       `json:"name"`
	Top         bool         `json:"top"`
	Agents      []basicAgent `json:"agents"`
	LType       string       `json:"ltype"`
	Port        string       `json:"port"`
}

type basicAgent struct {
	AgentKey   string      `json:"agentkey"`
	AgentName  string      `json:"agentname"`
	OS         string      `json:"os"`
	OSType     string      `json:"ostype"`
	IsElevated bool        `json:"iselevated"`
	Hostname   string      `json:"hostname"`
	Username   string      `json:"username"`
	LocalIP    string      `json:"localip"`
	Linked     *PivotGraph `json:"linked"` //if nested we would add it in here
}

//Takes in the dashboard data and parses it
func dashparse(fname string, data interface{}, ws *websocket.Conn) {
	logging.Logger.Println("Starting dashboard parsing")

	//Timeline is the only dashboard at this time.
	switch fname {
	case "agenttimeline":
		timeline(ws)
	case "agentostype":
		osType(ws)
	case "agentbylistener":
		agentListener(ws)
	case "pivotgraph":
		pivotGraph(ws, data)
	}

}

func timeline(ws *websocket.Conn) {
	tdata := sqldb.AgentTimeline()
	data := strings.Join(tdata, " ")
	logging.Logger.Println(data)
	outMsg := websockets.SendMessage{
		Type:         "metrics",
		FunctionName: "agenttimeline",
		Data:         data,
		Success:      true,
	}
	websockets.AlertSingleUser(outMsg, ws)
}

func osType(ws *websocket.Conn) {
	data := sqldb.AgentOSTypes()
	logging.Logger.Println(data)
	outMsg := websockets.SendMessage{
		Type:         "metrics",
		FunctionName: "agentostype",
		Data:         data,
		Success:      true,
	}
	websockets.AlertSingleUser(outMsg, ws)
}

func agentListener(ws *websocket.Conn) {
	data := sqldb.AgentByListener()
	logging.Logger.Println("agentlistener:", data)
	outMsg := websockets.SendMessage{
		Type:         "metrics",
		FunctionName: "agentbylistener",
		Data:         data,
		Success:      true,
	}
	websockets.AlertSingleUser(outMsg, ws)
}

func pivotGraph(ws *websocket.Conn, data interface{}) {
	var graphMap = map[string]*PivotGraph{}

	//Get all listeners
	listeners, types, ports, names := sqldb.GetListenerKeys()

	for _, x := range listeners {
		logging.Logger.Println("X is:", x)
		graphMap[x] = &PivotGraph{
			Listenerkey: x,
			Name:        names[x],
			Top:         true,
			Agents:      []basicAgent{},
			LType:       types[x],
			Port:        ports[x],
		}
	}

	//Get all agents
	//Data from agents would need to be the listenerkey, agentkey, OS, OSType
	agentrows := sqldb.GetAgentPivotData()

	defer agentrows.Close()
	for agentrows.Next() {
		var newAgent basicAgent
		var lKey string
		err := agentrows.Scan(&newAgent.AgentKey, &newAgent.AgentName, &lKey, &newAgent.OS, &newAgent.IsElevated, &newAgent.Hostname, &newAgent.Username, &newAgent.LocalIP)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
			break
		}
		if val, ok := graphMap[newAgent.AgentKey]; ok {
			newAgent.Linked = val
			val.Top = false

		}
		graphMap[lKey].Agents = append(graphMap[lKey].Agents, newAgent)

	}

	//Now send each of the top levels to the front end.
	var finalMsg string
	m := data.(map[string]interface{})
	logging.Logger.Println("DATA IS:", len(m))
	if len(m) != 0 {

		if !validation.ValidateMapAlert(m, []string{"listener"}, ws) {
			return
		}

		if val, ok := graphMap[m["listener"].(string)]; ok {
			finalMsg = "["
			msg, _ := json.Marshal(val)
			finalMsg += string(msg)
			finalMsg += "]"
		}

	} else {
		finalMsg = "["
		for _, y := range graphMap {
			if y.Top {
				msg, _ := json.Marshal(y)
				finalMsg += string(msg) + ","
			}
		}
		finalMsg = strings.TrimSuffix(finalMsg, ",")
		finalMsg += "]"
	}

	outMsg := websockets.SendMessage{
		Type:         "metrics",
		FunctionName: "pivotgraph",
		Data:         finalMsg,
		Success:      true,
	}
	websockets.AlertSingleUser(outMsg, ws)
}
