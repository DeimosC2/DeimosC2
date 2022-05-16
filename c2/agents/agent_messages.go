package agents

import (
	"encoding/json"

	"github.com/DeimosC2/DeimosC2/c2/webserver/websockets"
	"github.com/gorilla/websocket"
)

type (
	AgentComments struct {
		AgentKey string `json:"agentkey"`
		Data     string `json:"data"`
	}
)

func (ac *AgentComments) SendToFE(fn string, success bool, ws *websocket.Conn) {
	msg, _ := json.Marshal(ac)
	outMsg := websockets.SendMessage{
		Type:         "Agent",
		FunctionName: fn,
		Data:         string(msg),
		Success:      success,
	}
	websockets.AlertSingleUser(outMsg, ws)
}
