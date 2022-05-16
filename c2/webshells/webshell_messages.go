package webshells

import (
	"encoding/json"

	"github.com/DeimosC2/DeimosC2/c2/webserver/websockets"
	"github.com/gorilla/websocket"
)

type (
	WebShellInitResponse struct {
		UUID      string `json:"uuid"`
		URL       string `json:"url"`
		AuthToken string `json:"authtoken"`
		InitData  string `json:"initdata"`
	}

	WebShellFileBrowserResponse struct {
		UUID     string   `json:"uuid"`
		Method   string   `json:"method"`
		InitData []string `json:"initdata"`
	}
)

func (ir *WebShellInitResponse) SendToFE(success bool, ws *websocket.Conn) {

	output, _ := json.Marshal(ir)

	outMsg := websockets.SendMessage{
		Type:         "webshell",
		FunctionName: "init",
		Data:         string(output),
		Success:      success,
	}
	websockets.AlertSingleUser(outMsg, ws)
}

func (ir *WebShellFileBrowserResponse) SendToFE(success bool, ws *websocket.Conn) {

	output, _ := json.Marshal(ir)

	outMsg := websockets.SendMessage{
		Type:         "webshell",
		FunctionName: "filebrowser",
		Data:         string(output),
		Success:      success,
	}
	websockets.AlertSingleUser(outMsg, ws)
}
