package webserver

import (
	"encoding/json"
	"strings"

	"github.com/AdvancedThreatAnalytics/DeimosC2/c2/lib/sqldb"
	"github.com/AdvancedThreatAnalytics/DeimosC2/c2/lib/validation"
	"github.com/AdvancedThreatAnalytics/DeimosC2/c2/webserver/websockets"
	"github.com/AdvancedThreatAnalytics/DeimosC2/lib/logging"
	"github.com/gorilla/websocket"
)

//PivotGraph struct holds data for the API call
type PivotGraph struct {
	Listenerkey string
	Name        string
	Top         bool
	Agents      []basicAgent
	LType       string
	Port        string
}

type basicAgent struct {
	AgentKey   string
	AgentName  string
	OS         string
	OSType     string
	IsElevated bool
	Hostname   string
	Username   string
	LocalIP    string
	Linked     *PivotGraph //if nested we would add it in here
}

//Takes in the dashboard data and parses it
func dashparse(fname string, data interface{}, ws *websocket.Conn) {
	logging.Logger.Println("Starting dashboard parsing")

	//Timeline is the only dashboard at this time.
	switch fname {
	case "AgentTimeline":
		timeline(ws)
	case "AgentOSType":
		osType(ws)
	case "AgentByListener":
		agentListener(ws)
	case "PivotGraph":
		pivotGraph(ws, data)
	}

}

func timeline(ws *websocket.Conn) {
	tdata := sqldb.AgentTimeline()
	data := strings.Join(tdata, " ")
	logging.Logger.Println(data)
	outMsg := websockets.SendMessage{
		Type:         "Metrics",
		FunctionName: "AgentTimeline",
		Data:         data,
		Success:      true,
	}
	websockets.AlertSingleUser(outMsg, ws)
}

func osType(ws *websocket.Conn) {
	data := sqldb.AgentOSTypes()
	logging.Logger.Println(data)
	outMsg := websockets.SendMessage{
		Type:         "Metrics",
		FunctionName: "AgentOSType",
		Data:         data,
		Success:      true,
	}
	websockets.AlertSingleUser(outMsg, ws)
}

func agentListener(ws *websocket.Conn) {
	data := sqldb.AgentByListener()
	logging.Logger.Println("AgentListener:", data)
	outMsg := websockets.SendMessage{
		Type:         "Metrics",
		FunctionName: "AgentByListener",
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

		if !validation.ValidateMapAlert(m, []string{"Listener"}, ws) {
			return
		}

		if val, ok := graphMap[m["Listener"].(string)]; ok {
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
		Type:         "Metrics",
		FunctionName: "PivotGraph",
		Data:         finalMsg,
		Success:      true,
	}
	websockets.AlertSingleUser(outMsg, ws)
}
