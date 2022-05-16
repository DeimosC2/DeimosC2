package validation

import (
	"github.com/DeimosC2/DeimosC2/c2/webserver/websockets"
	"github.com/DeimosC2/DeimosC2/lib/logging"
	"github.com/gorilla/websocket"
)

//ValidateMapAlert is used to validate json objects passed through the api and alert the front end
func ValidateMapAlert(m map[string]interface{}, keys []string, ws *websocket.Conn) bool {
	for _, x := range keys {
		if _, ok := m[x]; !ok {
			logging.Logger.Println("Missing API variable", x)
			outMsg := websockets.SendMessage{
				Type:         "listener",
				FunctionName: "error",
				Data:         "{\"api_variable_issue\":" + "\"" + x + "\"}",
				Success:      false,
			}
			websockets.AlertSingleUser(outMsg, ws)
			return false
		}
	}
	return true
}

//ValidateMap is used to validate json objects passed through the api and alert the front end
func ValidateMap(m map[string]interface{}, keys []string) bool {
	for _, x := range keys {
		if _, ok := m[x]; !ok {
			return false
		}
	}
	return true
}
