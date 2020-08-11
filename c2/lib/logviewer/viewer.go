package logviewer

import (
	"io/ioutil"
	"os"
	"path"

	"github.com/DeimosC2/DeimosC2/c2/lib/validation"
	"github.com/DeimosC2/DeimosC2/c2/webserver/websockets"
	"github.com/DeimosC2/DeimosC2/lib/logging"
	"github.com/gorilla/websocket"
)

//View the file that is requested from the hardcoded list available
func viewFile(fileType string) (string, bool) {
	cwd, _ := os.Getwd()

	switch fileType {
	case "error":
		errorLog := path.Join(cwd, "resources", "logs", "errorhistory.log")
		data, err := ioutil.ReadFile(errorLog)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
			return err.Error(), false
		}
		return string(data), true
	case "backup":
		backupLog := path.Join(cwd, "resources", "logs", "backuphistory.log")
		data, err := ioutil.ReadFile(backupLog)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
			return err.Error(), false
		}
		return string(data), true
	case "commands":
		cmdLog := path.Join(cwd, "resources", "logs", "cmdhistory.log")
		data, err := ioutil.ReadFile(cmdLog)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
			return err.Error(), false
		}
		return string(data), true
	case "module":
		modLog := path.Join(cwd, "resources", "logs", "modhistory.log")
		data, err := ioutil.ReadFile(modLog)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
			return err.Error(), false
		}
		return string(data), true
	}
	return "", false
}

//ParseSocket parses calls to view log files
func ParseSocket(fname string, data interface{}, ws *websocket.Conn) {

	switch fname {
	case "ViewFile": // {"Type": "LogViewer", "FunctionName":"ViewFile", "Data":{"FileType": "error"}}
		m := data.(map[string]interface{})
		if !validation.ValidateMapAlert(m, []string{"FileType"}, ws) {
			return
		}
		rData, success := viewFile(m["FileType"].(string))
		msg := websockets.SendMessage{
			Type:         "LogViewer",
			FunctionName: "ViewFile",
			Data:         rData,
			Success:      success,
		}
		websockets.AlertSingleUser(msg, ws)
		return
	}
}
