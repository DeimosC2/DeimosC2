// +build windows

package fingerprint

import (
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

//Using code from https://github.com/mitchellh/go-ps/blob/4fdf99ab29366514c69ccccddab5dc58b8d84062/process_windows.go to conduct process searching
//Removed import for obfuscation reasons

// Process is the generic interface that is implemented on every platform
// and provides common operations for processes.
type process interface {
	// Pid is the process ID for this process.
	Pid() int

	// PPid is the parent process ID for this process.
	PPid() int

	// Executable name running this process. This is not a path to the
	// executable.
	Executable() string
}

// Windows API functions
var (
	modKernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procCloseHandle              = modKernel32.NewProc("CloseHandle")
	procCreateToolhelp32Snapshot = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First           = modKernel32.NewProc("Process32FirstW")
	procProcess32Next            = modKernel32.NewProc("Process32NextW")
)

// Some constants from the Windows API
const (
	ERROR_NO_MORE_FILES = 0x12
	MAX_PATH            = 260
)

// PROCESSENTRY32 is the Windows API structure that contains a process's
// information.
type PROCESSENTRY32 struct {
	Size              uint32
	CntUsage          uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	CntThreads        uint32
	ParentProcessID   uint32
	PriorityClassBase int32
	Flags             uint32
	ExeFile           [MAX_PATH]uint16
}

// WindowsProcess is an implementation of Process for Windows.
type WindowsProcess struct {
	pid  int
	ppid int
	exe  string
}

func (p *WindowsProcess) Pid() int {
	return p.pid
}

func (p *WindowsProcess) PPid() int {
	return p.ppid
}

func (p *WindowsProcess) Executable() string {
	return p.exe
}

func newWindowsProcess(e *PROCESSENTRY32) *WindowsProcess {
	// Find when the string ends for decoding
	end := 0
	for {
		if e.ExeFile[end] == 0 {
			break
		}
		end++
	}

	return &WindowsProcess{
		pid:  int(e.ProcessID),
		ppid: int(e.ParentProcessID),
		exe:  syscall.UTF16ToString(e.ExeFile[:end]),
	}
}

func findProcess(pid int) process {
	ps := processes()

	for _, p := range ps {
		if p.Pid() == pid {
			return p
		}
	}

	return nil
}

func processes() []process {
	handle, _, _ := procCreateToolhelp32Snapshot.Call(
		0x00000002,
		0)
	if handle < 0 {
		return nil
	}
	defer procCloseHandle.Call(handle)

	var entry PROCESSENTRY32
	entry.Size = uint32(unsafe.Sizeof(entry))
	ret, _, _ := procProcess32First.Call(handle, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return nil
	}

	results := make([]process, 0, 50)
	for {
		results = append(results, newWindowsProcess(&entry))

		ret, _, _ := procProcess32Next.Call(handle, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	return results
}

//End of https://github.com/mitchellh/go-ps code

//FingerPrint will get the version of the Operating System - This case call Windows API GetVersion
func FingerPrint() (string, string, []string) {

	//Get OS Vers (e.g. 7 or 10)
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		//logging.Logger.Println(err.Error())
	}
	defer k.Close()

	osVers, _, err := k.GetIntegerValue("CurrentMajorVersionNumber")
	if err != nil {
		//logging.Logger.Println(err.Error())
	}

	//Get OS Type (Pro vs Enterprise)
	pn, _, err := k.GetStringValue("ProductName")
	if err != nil {
		//logging.Logger.Println(err.Error())
	}
	osType := lastString(strings.Split(pn, " "))

	//Get AV
	//Can add to this by adding to the switch case for any other type of AV you want to find
	var av []string
	p := processes()
	for _, p1 := range p {
		switch {
		case p1.Executable() == "cb.exe":
			av = append(av, "CB")
		case p1.Executable() == "CylanceSvc.exe":
			av = append(av, "Cylance")
		}
	}
	return osType, strconv.FormatUint(osVers, 10), av
}

func lastString(ss []string) string {
	return ss[len(ss)-1]
}
