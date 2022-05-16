//go:build linux
// +build linux

package filebrowser

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

type Directory struct {
	DirectoryName string
	Perms         string
	CreationTime  string
	LastAccess    string
	LastWrite     string
}

type Files struct {
	Filename     string
	Filesize     string
	FilePerms    string
	CreationTime string
	LastAccess   string
	LastWrite    string
}

//FileBrowser will take in path and load up all the directories and files in a structure matching webshells
func FileBrowser(path string) string {
	var fileArray []Files
	var dirArray []Directory
	//Get one directory above for the parent directory
	parentDir := "\"parentdir\":\"" + filepath.Dir(path) + "\","
	//Get current directory
	cwd := "\"cwd\":\"" + path + "\","

	//Read the directory from the provided path
	files, _ := ioutil.ReadDir(path)

	for _, file := range files {
		var stat unix.Stat_t
		unix.Stat(file.Name(), &stat)
		atime := time.Unix(int64(stat.Atim.Sec), int64(stat.Atim.Nsec))
		ctime := time.Unix(int64(stat.Ctim.Sec), int64(stat.Ctim.Nsec))

		//If it is a directory point it to the Directory{} struct
		if file.IsDir() {
			dirs := Directory{
				DirectoryName: file.Name(),
				Perms:         file.Mode().Perm().String(),
				CreationTime:  ctime.String(),
				LastAccess:    atime.String(),
				LastWrite:     file.ModTime().String(),
			}
			dirArray = append(dirArray, dirs)
		} else {
			//If files point to the Files{} struct
			file := Files{
				Filename:     file.Name(),
				Filesize:     strconv.FormatInt(file.Size(), 10),
				FilePerms:    file.Mode().Perm().String(),
				CreationTime: ctime.String(),
				LastAccess:   atime.String(),
				LastWrite:    file.ModTime().String(),
			}
			fileArray = append(fileArray, file)
		}
	}
	//JSON Marshal both the directory array and the file array
	dirMsg, _ := json.Marshal(dirArray)
	fileMsg, _ := json.Marshal(fileArray)

	//Send to functions.go the JSON filebrowser
	jsonMsg := "\"drives\": [\"null\"]," + cwd + parentDir + "\"directories\":" + string(dirMsg) + ",\"files\":" + string(fileMsg)
	return jsonMsg
}
