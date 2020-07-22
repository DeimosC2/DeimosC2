// +build windows

package selfdestruction

import (
	"os"
	"syscall"
)

//SelfDelete will delete the agent when called
func SelfDelete() {
	var sI syscall.StartupInfo
	var pI syscall.ProcessInformation
	path, _ := os.Getwd()
	comspec := os.Getenv("ComSpec")
	//logging.Logger.Println("Deleting agent: ", os.Args[0])

	argv := syscall.StringToUTF16Ptr(comspec + " /C del " + path + "\\" + os.Args[0])

	//logging.Logger.Println("Command is: ", comspec+" /C del "+path+"\\"+os.Args[0])
	err := syscall.CreateProcess(nil, argv, nil, nil, true, 0, nil, nil, &sI, &pI)
	if err != nil {
		//logging.Logger.Println("Couldn't self destruct because: ", err.Error())
	}
}
