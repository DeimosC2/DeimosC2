package websockets

import (
	"encoding/json"
	"time"
)

type (
	HeartBeat struct {
		AgentKey string    `json:"agentkey"`
		Time     time.Time `json:"time"`
	}
)

func (hb *HeartBeat) Send() {
	toSend, _ := json.Marshal(hb)

	outMsg := SendMessage{
		Type:         "agent",
		FunctionName: "heartbeat",
		Data:         string(toSend),
		Success:      true,
	}
	AlertUsers(outMsg)
}
