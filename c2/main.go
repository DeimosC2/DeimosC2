//This is the main package that will start up the server

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/DeimosC2/DeimosC2/c2/agents"

	"github.com/DeimosC2/DeimosC2/c2/lib"
	"github.com/DeimosC2/DeimosC2/c2/lib/archive"
	"github.com/DeimosC2/DeimosC2/c2/lib/certs"
	"github.com/DeimosC2/DeimosC2/c2/lib/gobuild"
	"github.com/DeimosC2/DeimosC2/c2/lib/sqldb"
	"github.com/DeimosC2/DeimosC2/c2/modules"
	"github.com/DeimosC2/DeimosC2/c2/webserver"
	"github.com/DeimosC2/DeimosC2/c2/webshells"
	"github.com/DeimosC2/DeimosC2/lib/logging"
)

//If the server is restarted or brought back up then this function brings everything back up
func reInitServer(dbfile string) {
	sqldb.OpenDB(dbfile)
	agents.ReInitAgents()
	rows := sqldb.GetListeners()

	var oldListener lib.Listener
	defer rows.Close()
	for rows.Next() {
		var tempAdvanced string
		err := rows.Scan(&oldListener.LType, &oldListener.Name, &oldListener.Host, &oldListener.Port, &oldListener.Key, &oldListener.PubKey, &oldListener.PrivKey, &tempAdvanced, &oldListener.AgentOptions.Delay, &oldListener.AgentOptions.Jitter, &oldListener.AgentOptions.Eol, &oldListener.AgentOptions.LiveHours)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}
		json.Unmarshal([]byte(tempAdvanced), &oldListener.Advanced)
		lib.ReInitListener(oldListener)
	}

	webshells.ReInitWebShells()
}

func ask() bool {
	var response string
	_, err := fmt.Scanln(&response)
	if err != nil {
		if err.Error() == "unexpected newline" {
			return ask()
		}
		logging.ErrorLogger.Println(err.Error())
	}
	switch strings.ToLower(response) {
	case "y", "yes":
		return true
	case "n", "no":
		return false
	default:
		fmt.Println("I'm sorry but I didn't get what you mean, please type (y)es or (n)o and then press enter:")
		return ask()
	}
}

//Copied straight out of Stackoverflow
func copy(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return out.Close()
}

//Copied straight out of Stackoverflow
func externalIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return ip.String(), nil
		}
	}
	return "", errors.New("are you connected to the network?")
}

func main() {
	logging.InitLogger()
	logging.Logger.Println("C2 Server Starting...")

	var firstTime bool

	cwd, err := os.Getwd()
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
		os.Exit(10)
	}

	// Temp code to check for GOPATH and if empty set it ourselves
	goRoot := os.Getenv("GOROOT")
	logging.Logger.Println("Main.go goroot: ", goRoot)
	if goRoot == "" {
		newGoRoot := path.Join(cwd, "goroot", "go")
		os.Setenv("GOROOT", newGoRoot)
	}
	goPath := os.Getenv("GOPATH")
	logging.Logger.Println("Main.go gopath: ", goPath)
	if goPath == "" {
		newGoPath := path.Join(cwd, "gopath")
		os.Setenv("GOPATH", newGoPath)
	}

	//check to see if exist, if so then reinit else ask questions
	dbPath := path.Join(cwd, "resources", "c2.db")

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		userInput := bufio.NewReader(os.Stdin)
		logging.Logger.Println("It seems like this is your first time running DeimosC2.")
		logging.Logger.Println("Would you like to restore from archive? [Y/N]")
		if ask() {
			logging.Logger.Println("Please pass full path of the zip file along with filename!")
			zipPath, _ := userInput.ReadString('\n')
			zipPath = strings.TrimSpace(zipPath)
			archive.Replay(zipPath)
			firstTime = false
			reInitServer(dbPath)
		} else {
			logging.Logger.Println("It seems like this is your first time running.")
			logging.Logger.Println("Would you like to initialize the DB and Webserver? [Y/N]")
			if ask() {
				//Ask all the questions then build the DB
				logging.Logger.Println("Do you have custom SSL certs to add? [Y/N]")
				if ask() {
					logging.Logger.Println("Please pass the full path to the cert file")
					certPath, _ := userInput.ReadString('\n')
					certPath = strings.TrimSpace(certPath)
					logging.Logger.Println("Please pass the full path to the key file")
					keyPath, _ := userInput.ReadString('\n')
					keyPath = strings.TrimSpace(keyPath)
					//Copy the files to our fun location
					copy(certPath, path.Join(cwd, "resources", "server.cer"))
					copy(keyPath, path.Join(cwd, "resources", "server.key"))

				} else {
					//Should ask users to enter their personal cert data
					certs.GenerateLocalCert("0.0.0.0", time.Now().Format("Jan 2 15:04:05 2006"), 365*24*time.Hour, false, 2048, "P256", false, path.Join(cwd, "resources", "server.cer"), path.Join(cwd, "resources", "server.key"))
				}
				sqldb.Initalize(dbPath)
				firstTime = true
			} else {
				logging.Logger.Println("Please check your database or reinit the server.")
				os.Exit(10)
			}
		}
	} else {
		firstTime = false
		reInitServer(dbPath)
	}

	// logging.Logger.Println("Would you like to obfuscate all the possible agents?")
	// gobuild.PrepObfuscation(ask())
	//TODO Make this not a temp work around
	gobuild.PrepObfuscation(false)

	go modules.StartModuleServer()
	go archive.StartBackup()

	c := webserver.Config{
		DbFile:        dbPath,
		Cert:          "server.cer",
		Key:           "server.key",
		WebserverPort: "8443",
		Setup:         firstTime,
	}

	//Inform the user where to go to access the webserver
	ip, err := externalIP()
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	logging.Logger.Println("Please go to https://" + ip + ":8443/")

	webserver.RunServer(c)
}
