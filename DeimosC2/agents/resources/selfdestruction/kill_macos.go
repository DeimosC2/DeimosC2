// +build darwin

package selfdestruction

import (
	"os"
)

//SelfDelete will delete the agent when called
func SelfDelete() {
	path, _ := os.Getwd()
	fullPath := path + "/" + os.Args[0]
	err := os.Remove(fullPath)
	if err != nil {
		//logging.Logger.Println(err)
	}
}
