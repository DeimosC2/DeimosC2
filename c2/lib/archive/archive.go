package archive

import (
	"archive/zip"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/DeimosC2/DeimosC2/c2/lib/sqldb"
	"github.com/DeimosC2/DeimosC2/c2/lib/validation"
	"github.com/DeimosC2/DeimosC2/c2/webserver/websockets"
	"github.com/DeimosC2/DeimosC2/lib/logging"
	"github.com/gorilla/websocket"
)

var isRunning bool

//Zips the files and either deletes them if endgame or just backs them up to a zip file
func filesToZip(backup bool, schBackup bool) (string, bool) {
	var deleteArray []string

	//Need to close the database
	success := sqldb.CloseDB()
	if success == false {
		return "Couldn't Close DB", false
	}

	cwd, _ := os.Getwd()
	//Create the zip file where everything will be stored
	zipName := "archive_" + time.Now().Format("2006_01_02_150405"+".zip")
	zipFile := path.Join(cwd, "archives", zipName)
	archiveZip, err := os.Create(zipFile)
	if err != nil {
		return err.Error(), false
	}
	defer archiveZip.Close()

	zipWriter := zip.NewWriter(archiveZip)
	defer zipWriter.Close()

	//Static files to zip
	staticFiles := []string{"c2.db", "server.cer", "server.key"}
	for _, staticFile := range staticFiles {
		staticFolder := path.Join(cwd, "resources", staticFile)
		addToZip(zipWriter, staticFolder, "resources/")
		deleteArray = append(deleteArray, staticFolder)
	}

	//Start with logs directory
	logsFolder := path.Join(cwd, "resources", "logs")
	logFiles, err := ioutil.ReadDir(logsFolder)
	if err != nil {
		return err.Error(), false
	}
	for _, logFile := range logFiles {
		if !logFile.IsDir() {
			combinedLog := path.Join(logsFolder, logFile.Name())
			addToZip(zipWriter, combinedLog, "resources/logs/")
			deleteArray = append(deleteArray, combinedLog)
		}
	}
	logging.CloseLog()

	//Get files in looted directory
	lootedFolder := path.Join(cwd, "resources", "looted")
	lootedFiles, err := ioutil.ReadDir(lootedFolder)
	if err != nil {
		return err.Error(), false
	}
	for _, lootedFile := range lootedFiles {
		if lootedFile.IsDir() {
			lootedDir := lootedFile.Name()
			combinedLootedDir := path.Join(lootedFolder, lootedDir)
			addToZip(zipWriter, combinedLootedDir, "resources/looted/")
			deleteArray = append(deleteArray, combinedLootedDir)
			nestedLootedDir, _ := ioutil.ReadDir(combinedLootedDir)
			for _, lootfile := range nestedLootedDir {
				combinedLooted := path.Join(lootedFolder, lootedDir, lootfile.Name())
				addToZip(zipWriter, combinedLooted, "resources/looted/"+lootedDir+"/")
				deleteArray = append(deleteArray, combinedLooted)
			}
		}
	}

	//Get files in listenerresources directory
	listenerFolder := path.Join(cwd, "resources", "listenerresources")
	listenerFiles, err := ioutil.ReadDir(listenerFolder)
	if err != nil {
		return err.Error(), false
	}
	for _, listenersFile := range listenerFiles {
		if listenersFile.IsDir() {
			listenerDir := listenersFile.Name()
			combinedListenerDir := path.Join(listenerFolder, listenerDir)
			addToZip(zipWriter, combinedListenerDir, "resources/listenerresources/")
			deleteArray = append(deleteArray, combinedListenerDir)
			nestedListenerDir, _ := ioutil.ReadDir(combinedListenerDir)
			for _, listenerfile := range nestedListenerDir {
				combinedListeners := path.Join(listenerFolder, listenerDir, listenerfile.Name())
				addToZip(zipWriter, combinedListeners, "resources/listenerresources/"+listenerDir+"/")
				deleteArray = append(deleteArray, combinedListeners)
			}
		}
	}

	//Get files in webshells/generated directory
	webshellGenFolder := path.Join(cwd, "resources", "webshells", "generated")
	webshellGFiles, err := ioutil.ReadDir(webshellGenFolder)
	if err != nil {
		return err.Error(), false
	}
	for _, webshellGFile := range webshellGFiles {
		if !webshellGFile.IsDir() {
			combinedWebShell := path.Join(webshellGenFolder, webshellGFile.Name())
			addToZip(zipWriter, combinedWebShell, "resources/webshells/generated/")
			deleteArray = append(deleteArray, combinedWebShell)
		}
	}

	if !backup {
		err := deleteFiles(deleteArray)
		if err != nil {
			return err.Error(), false
		}
		return "/archives/" + zipName, true
	} else if schBackup {
		//Need to bring c2.db backup for the server to work correctly
		dbPath := path.Join(cwd, "resources", "c2.db")
		sqldb.OpenDB(dbPath)
		return "Backup Done!", true
	} else {
		//Need to bring c2.db backup for the server to work correctly
		dbPath := path.Join(cwd, "resources", "c2.db")
		sqldb.OpenDB(dbPath)
		return "/archives/" + zipName, true
	}
}

func addToZip(zipwriter *zip.Writer, file string, base string) {
	//Open and read file
	filetoZip, err := os.Open(file)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	defer filetoZip.Close()

	//Get the file information
	info, err := filetoZip.Stat()
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	// Using FileInfoHeader() above only uses the basename of the file. If we want
	// to preserve the folder structure we can overwrite this with the full path.
	header.Name = base + filepath.Base(file)

	//Change to deflate to gain better compression
	//see http://golang.org/pkg/archive/zip/#pkg-constants
	header.Method = zip.Deflate

	writer, err := zipwriter.CreateHeader(header)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	_, err = io.Copy(writer, filetoZip)
}

//Delete the files that we zipped up to remove the extra garbage after a campaign
func deleteFiles(files []string) error {
	for _, file := range files {
		fileInfo, err := os.Stat(file)
		if err != nil {
			return err
		}
		if fileInfo.IsDir() {
			err := os.RemoveAll(file)
			if err != nil {
				return err
			}
		} else {
			err := os.Remove(file)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

//Replay will allow a user to unzip archive.zip and stand backup their infrastructure from an old campaign
func Replay(zipFile string) bool {
	cwd, _ := os.Getwd()
	read, err := zip.OpenReader(zipFile)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	defer read.Close()

	for _, f := range read.File {
		//Store filename/path for returning and using
		fpath := filepath.Join(cwd, f.Name)
		if strings.Contains(fpath, "logs") {
			continue
		}

		//Check for zipslip vuln
		if !strings.HasPrefix(fpath, filepath.Clean(cwd)+string(os.PathSeparator)) {
			logging.Logger.Println("Illegal File Path: ", fpath)
			return false
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		//Make the file
		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			logging.ErrorLogger.Println(err.Error())
			return false
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
			return false
		}

		rc, err := f.Open()
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
			return false
		}

		_, err = io.Copy(outFile, rc)

		//Close the file without defer to close before next iteration of loop
		outFile.Close()
		rc.Close()

		if err != nil {
			logging.ErrorLogger.Println(err.Error())
			return false
		}
	}
	return true
}

//StartBackup backup will run filesToZip with backup equals true
func StartBackup() {
	if !isRunning {
		isRunning = true
		var ran bool
		for {
			status, day, hour := sqldb.CheckBackup()
			if status {
				current := time.Now()
				if strings.ToLower(day) == strings.ToLower(time.Now().Weekday().String()) && hour == current.Format("15:04") {
					if !ran {
						rData, success := filesToZip(false, true)
						if success {
							ran = true
						} else {
							//Save the success statement to a log file named backup.log
							logging.BackupLog(rData)
						}
					}
					startTime := strings.Split(hour, ":")
					startHour, _ := strconv.Atoi(startTime[0])
					startMin, _ := strconv.Atoi(startTime[1])
					start := time.Date(current.Year(), current.Month(), current.Day(), startHour, startMin, current.Second(), current.Nanosecond(), current.Location())
					time.Sleep(start.Sub(current))
				}
			} else {
				ran = false
				isRunning = false
				return
			}
		}
	}
}

//ParseSocket parses calls to make DB edits from the frontend
func ParseSocket(fname string, data interface{}, ws *websocket.Conn) {

	if fname == "SetSchedule" {
		//Set the schedule for which archive is supposed to run
		m := data.(map[string]interface{})
		if !validation.ValidateMapAlert(m, []string{"Status", "Hour", "Days"}, ws) {
			return
		}

		var daysList []string
		switch val := m["Days"].(type) {
		case []interface{}:
			for _, x := range val {
				daysList = append(daysList, x.(string))
			}
		}

		dayMarshal, _ := json.Marshal(daysList)
		success := sqldb.SetSchedule(m["Hour"].(string), dayMarshal, m["Status"].(bool))
		StartBackup()
		msg := websockets.SendMessage{
			Type:         "Archive",
			FunctionName: "SetSchedule",
			Data:         "",
			Success:      success,
		}
		websockets.AlertSingleUser(msg, ws)
		return
	}

	m := data.(map[string]interface{})
	if !validation.ValidateMapAlert(m, []string{"Backup"}, ws) {
		return
	}

	switch fname {
	case "EndGame":
		//Will start archiving everything
		_, success := filesToZip(m["Backup"].(bool), false)
		msg := websockets.SendMessage{
			Type:         "Archive",
			FunctionName: "EndGame",
			Data:         "Data Stored on Server",
			Success:      success,
		}
		websockets.AlertSingleUser(msg, ws)
		logging.Logger.Println("Murdering web server!")
		//Murder webserver
		os.Exit(10)
	case "Backup":
		//Will start archiving everything
		zipBackup, success := filesToZip(m["Backup"].(bool), false)
		//Send zipfile to the FE as b64 content
		msg := websockets.SendMessage{
			Type:         "Archive",
			FunctionName: "Backup",
			Data:         zipBackup,
			Success:      success,
		}
		websockets.AlertSingleUser(msg, ws)
	}
}
