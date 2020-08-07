// +build windows

package filebrowser

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
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
	parentDir := "\"ParentDir\":\"" + filepath.Dir(path) + "\","
	//Get current directory
	cwd := "\"CWD\":\"" + path + "\","

	//Get the drives mounted to the system
	kernel32, _ := syscall.LoadDLL("kernel32.dll")
	getLogicalDriveStringsHandle, _ := kernel32.FindProc("GetLogicalDriveStringsA")
	buffer := [1024]byte{}
	bufferSize := uint32(len(buffer))
	hr, _, _ := getLogicalDriveStringsHandle.Call(uintptr(unsafe.Pointer(&bufferSize)), uintptr(unsafe.Pointer(&buffer)))
	if hr == 0 {
		//logging.Logger.Println("Broken")
	}

	drives := "["
	parts := bytes.Split(buffer[:], []byte{0})
	for _, part := range parts {
		if len(part) == 0 {
			break
		}
		drives += "\"" + string(part) + "\\\","
	}
	drives = strings.TrimSuffix(drives, ",")
	drives += "]"

	//Read the directory from the provided path
	files, _ := ioutil.ReadDir(path)

	for _, file := range files {
		stat := file.Sys().(*syscall.Win32FileAttributeData)
		aTimeSince := time.Since(time.Unix(0, stat.LastAccessTime.Nanoseconds()))
		cTimeSince := time.Since(time.Unix(0, stat.CreationTime.Nanoseconds()))
		mTimeSince := time.Since(time.Unix(0, stat.LastWriteTime.Nanoseconds()))

		//If it is a directory point it to the Directory{} struct
		if file.IsDir() {
			dirs := Directory{
				DirectoryName: file.Name(),
				Perms:         file.Mode().Perm().String(),
				CreationTime:  cTimeSince.String(),
				LastAccess:    aTimeSince.String(),
				LastWrite:     mTimeSince.String(),
			}
			dirArray = append(dirArray, dirs)
		} else {
			//If files point to the Files{} struct
			file := Files{
				Filename:     file.Name(),
				Filesize:     strconv.FormatInt(file.Size(), 10),
				FilePerms:    file.Mode().Perm().String(),
				CreationTime: cTimeSince.String(),
				LastAccess:   aTimeSince.String(),
				LastWrite:    mTimeSince.String(),
			}
			fileArray = append(fileArray, file)
		}
	}
	//JSON Marshal both the directory array and the file array
	dirMsg, _ := json.Marshal(dirArray)
	fileMsg, _ := json.Marshal(fileArray)

	//Send to functions.go the JSON filebrowser
	jsonMsg := "\"Drives\":" + drives + "," + cwd + parentDir + "\"Directories\":" + string(dirMsg) + ",\"Files\":" + string(fileMsg)
	return jsonMsg
}
