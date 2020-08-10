package gobuild

import (
	"bytes"
	"encoding/base64"
	"go/build"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/DeimosC2/DeimosC2/c2/agents/techniques/httpstechniques"
	"github.com/DeimosC2/DeimosC2/c2/gobfuscate"
	"github.com/DeimosC2/DeimosC2/c2/lib/validation"
	"github.com/DeimosC2/DeimosC2/c2/webserver/websockets"
	"github.com/DeimosC2/DeimosC2/lib/logging"
)

//Tells us if things are precompiled
var preObfuscated = false

var fileLocations = obfLocations{}

type obfLocations struct {
	https string
	quic  string
	tcp   string
	doh   string
}

//Init will build agents on the inital startup of a listener
//Note we will overwrite old binaries
func Init(lType string, lName string, pubKey []byte, host string, port string, delay string, jitter string, eol string, livehours string, advanced interface{}, gooses []string, arches []string, obf bool) {
	logging.Logger.Println("Time to build here")

	cwd, err := os.Getwd()
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	lPath := path.Join(cwd, "resources", "listenerresources", lName) //where the final binaries need to be stored
	logging.Logger.Println(lPath)

	//Check to ensure the directory does not exist
	if _, err := os.Stat(lPath); os.IsNotExist(err) {
		//Make the directory under resources with listener name
		os.Mkdir(lPath, 0755)
	}

	//With all the data read in its time to copy the base agent file to the right location
	if lType == "PIVOTTCP" {
		lType = "TCP"
	}

	var loc string
	switch lType {
	case "HTTPS":
		loc = fileLocations.https
	case "QUIC":
		loc = fileLocations.quic
	case "TCP":
		loc = fileLocations.tcp
	case "DoH":
		loc = fileLocations.doh
	}

	//input, err := ioutil.ReadFile(path.Join(cwd, "agents", strings.ToLower(lType), strings.ToLower(lType)+"_agent.go"))
	input, err := ioutil.ReadFile(loc)

	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	output := strings.Replace(string(input), "{{DELAY}}", strings.TrimSpace(delay), -1)
	output = strings.Replace(string(output), "{{JITTER}}", strings.TrimSpace(jitter), -1)
	output = strings.Replace(string(output), "{{EOL}}", strings.TrimSpace(eol), -1)
	output = strings.Replace(string(output), "{{LIVEHOURS}}", strings.TrimSpace(livehours), -1)
	if lType != "HTTPS" {
		output = strings.Replace(string(output), "{{HOST}}", strings.TrimSpace(host), -1)
		output = strings.Replace(string(output), "{{PORT}}", strings.TrimSpace(port), -1)
	}
	if lType != "DoH" {
		output = strings.Replace(string(output), "{{PUBKEY}}", string(pubKey), -1)
	} else {
		//base64 it so we can move it as a string into the binary
		output = strings.Replace(string(output), "{{PUBKEY}}", base64.StdEncoding.EncodeToString(pubKey), -1)
	}

	if lType == "HTTPS" || lType == "QUIC" {
		m := advanced.(map[string]interface{})
		if lType == "HTTPS" {
			if !validation.ValidateMap(m, []string{"domainHiding", "frontDomainIP", "frontDomainPort", "actualDomain", "registerPath", "checkinPath", "modulePath", "pivotPath"}) {
				return
			}
			//Options for Domain Hiding
			if m["domainHiding"].(bool) {
				output = httpstechniques.StageDomainHiddenCode(output, m["frontDomainIP"].(string), m["frontDomainPort"].(string), m["actualDomain"].(string))
			} else {
				output = httpstechniques.StageNormalCode(output, host, port)
			}
			output = strings.Replace(string(output), "{{FIRSTTIME}}", strings.TrimSpace(m["registerPath"].(string)), -1)
			output = strings.Replace(string(output), "{{CHECKIN}}", strings.TrimSpace(m["checkinPath"].(string)), -1)
			output = strings.Replace(string(output), "{{MODULELOC}}", strings.TrimSpace(m["modulePath"].(string)), -1)
			output = strings.Replace(string(output), "{{PIVOTLOC}}", strings.TrimSpace(m["pivotPath"].(string)), -1)
		} else {
			if !validation.ValidateMap(m, []string{"registerPath", "checkinPath", "modulePath", "pivotPath"}) {
				return
			}
			output = strings.Replace(string(output), "{{FIRSTTIME}}", strings.TrimSpace(m["registerPath"].(string)), -1)
			output = strings.Replace(string(output), "{{CHECKIN}}", strings.TrimSpace(m["checkinPath"].(string)), -1)
			output = strings.Replace(string(output), "{{MODULELOC}}", strings.TrimSpace(m["modulePath"].(string)), -1)
			output = strings.Replace(string(output), "{{PIVOTLOC}}", strings.TrimSpace(m["pivotPath"].(string)), -1)
		}
	} else if lType == "DoH" {
		m := advanced.(map[string]interface{})
		if !validation.ValidateMap(m, []string{"firsttime", "checkin", "successResponse", "failureResponse", "jobExists"}) {
			return
		}
		output = strings.Replace(string(output), "{{FIRSTTIME}}", strings.TrimSpace(m["firsttime"].(string)), -1)
		output = strings.Replace(string(output), "{{CHECKIN}}", strings.TrimSpace(m["checkin"].(string)), -1)
		output = strings.Replace(string(output), "{{SUCCESSRESPONSE}}", strings.TrimSpace(m["successResponse"].(string)), -1)
		output = strings.Replace(string(output), "{{FAILURERESPONSE}}", strings.TrimSpace(m["failureResponse"].(string)), -1)
		output = strings.Replace(string(output), "{{JOBEXISTS}}", strings.TrimSpace(m["jobExists"].(string)), -1)
	}

	compileFile := path.Join(lPath, lType+"_agent.go")
	err = ioutil.WriteFile(compileFile, []byte(output), 0755)
	if err != nil {
		logging.ErrorLogger.Println("Didn't copy over: ", err.Error())
	}
	//TODO evaluate the current location of this command
	//Might be better to just force it to always off?
	if !obf {
		for _, goos := range gooses {
			for _, arch := range arches {

				command := []string{"build"}
				if goos == "windows" {
					command = append(command, `-ldflags=-s -w -H=windowsgui`)
				} else {
					command = append(command, `-ldflags=-s -w`)
				}
				command = append(command, "-trimpath")
				command = append(command, "-o")

				var filename string
				switch goos {
				case "windows":
					filename = lType + "Agent_Win_" + arch + "_Intel.exe"
				case "linux":
					filename = lType + "Agent_Lin_" + arch + "_Intel"
				case "darwin":
					filename = lType + "Agent_Mac_" + arch + "_Intel"
				case "android":
					filename = lType + "Agent_Android_" + arch + "_Arm"
					goos = "linux"
				}
				command = append(command, path.Join(lPath, filename))

				command = append(command, compileFile)

				compileBinary(goos, arch, command, cwd, "")

				msg := "{\"Key\": \"" + lName + "\", \"File\": \"" + filename + "\"}"
				outMsg := websockets.SendMessage{
					Type:         "Listener",
					FunctionName: "AgentCreate",
					Data:         msg,
					Success:      true,
				}
				logging.Logger.Println(outMsg)
				websockets.AlertUsers(outMsg)

			}
		}

	} else {
		os.Setenv("GO111MODULE", "off")
		defer os.Setenv("GO111MODULE", "")

		var wg sync.WaitGroup
		for _, goos := range gooses {
			for _, arch := range arches {
				wg.Add(1)
				go func(lName string, lType string, cwd string, goos string, arch string, lPath string) {
					defer wg.Done()
					obfuscate(lName, lType, cwd, goos, arch, lPath, false)
				}(lName, lType, cwd, goos, arch, lPath)
			}
			wg.Wait()
		}
	}

}

//Used to compile a binary with the given target/arch
func compileBinary(target string, arch string, command []string, cwd string, newGoPath string) {

	logging.Logger.Println(command)
	goBin := path.Join(os.Getenv("GOROOT"), "bin", "go")
	cmd := exec.Command(goBin, command...)

	logging.Logger.Println("CMD IS: ", cmd)

	cmd.Dir = cwd

	//Need a better way to do this currently hard coded
	cmd.Env = os.Environ() //This lets us use the default go env and only change the needed flags
	cmd.Env = append(cmd.Env, "GOOS="+target)
	cmd.Env = append(cmd.Env, "GOARCH="+arch)
	if newGoPath != "" {
		cmd.Env = append(cmd.Env, "GOPATH="+newGoPath)
	}
	cmd.Env = append(cmd.Env, "GOROOT="+os.Getenv("GOROOT"))
	//cmd.Env = append(cmd.Env, "CC=gcc")
	cmd.Env = append(cmd.Env, "CGO_ENABLED=0")
	logging.Logger.Println(cmd.Env)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	result, err := cmd.Output()
	if err != nil {
		logging.ErrorLogger.Println("ERROR:", err.Error())
		logging.ErrorLogger.Println("RESULT: ", result)
		logging.ErrorLogger.Println("STDERR: ", string(stderr.Bytes()))
	}
	logging.Logger.Println(string(result))

	logging.Logger.Println("CREATED")

}

func copyDep(destPath string, packagePath string, target string) {
	//Make the location for the new code
	if _, err := os.Stat(destPath); os.IsNotExist(err) {
		os.Mkdir(destPath, 0755)
	}

	context := build.Default
	context.GOOS = target
	context.GOPATH = os.Getenv("GOPATH")
	context.GOROOT = os.Getenv("GOROOT")

	logging.Logger.Println("The context is: ", context)

	pkg, err := context.Import(packagePath, "", 0)
	if err != nil {
		logging.ErrorLogger.Println("Import Failed: ", err.Error())
	}
	githubDependancies(pkg, destPath, target)
	golangDependancies(destPath)

}

//Copies all of the golang depencies into the destination path as well
func golangDependancies(destPath string) {

	//Should know the exact gopath
	goPath := os.Getenv("GOPATH")
	logging.Logger.Println("GoPATH in golang dep is: ", goPath)
	if goPath == "" {
		goPath = build.Default.GOPATH
	}
	filepath.Walk(path.Join(goPath, "src", "golang.org"), func(fPath string, info os.FileInfo, err error) error {
		//logging.Logger.Println(fPath)
		relPath, err := filepath.Rel(path.Join(goPath, "src"), fPath)
		//logging.Logger.Println("REL PATH IS:", relPath)
		if info.IsDir() {
			if _, err := os.Stat(path.Join(destPath, relPath)); os.IsNotExist(err) {
				//Make the directory under resources with listener name
				os.MkdirAll(path.Join(destPath, relPath), 0755)
			}
			return nil
		}
		if _, err := os.Stat(path.Join(destPath, relPath)); os.IsNotExist(err) {
			copy(fPath, path.Join(destPath, relPath))
		}
		return err
	})

}

//Copies all of the github dependancies over to a tmp folder structure
func githubDependancies(pkg *build.Package, destPath string, target string) {
	context := build.Default
	context.GOOS = target
	context.GOPATH = os.Getenv("GOPATH")
	context.GOROOT = os.Getenv("GOROOT")
	logging.Logger.Println("github dep context is:", context)
	if _, err := os.Stat(path.Join(destPath, pkg.ImportPath)); os.IsNotExist(err) {
		os.MkdirAll(path.Join(destPath, pkg.ImportPath), 0755)
	}
	for _, y := range pkg.Imports {
		if strings.Contains(y, "github.com") || strings.Contains(y, "golang.org") {
			nestedPkg, err := context.Import(y, "", 0)
			if err != nil {
				logging.ErrorLogger.Println("Import Failed: ", err.Error())
			}
			githubDependancies(nestedPkg, destPath, target)
		}
	}
	for _, x := range pkg.GoFiles {
		//logging.Logger.Println(path.Join(destPath, pkg.ImportPath, x))
		if _, err := os.Stat(path.Join(destPath, pkg.ImportPath, x)); os.IsNotExist(err) {
			copy(path.Join(pkg.Dir, x), path.Join(destPath, pkg.ImportPath, x))
		}
	}
	return
}

//Copied straight out of Stackoverflow
//dup from main
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

func obfuscate(lName string, lType string, cwd string, goos string, arch string, lPath string, preComp bool) {
	logging.Logger.Println("Obfuscating: ", lPath)
	var newGoDir string
	if !preComp {
		newGoDir, _ = ioutil.TempDir("", "")

		logging.Logger.Println("NEW DIR IS:", newGoDir)

		defer os.RemoveAll(newGoDir)
	}
	buf := make([]byte, 32)
	rand.Read(buf) //TODO change these so that its more dynamic

	var loc string
	switch lType {
	case "HTTPS":
		loc = fileLocations.https
	case "QUIC":
		loc = fileLocations.quic
	case "TCP":
		loc = fileLocations.tcp
	case "DoH":
		loc = fileLocations.doh
	}

	//returns all of the newly written packages
	relPath, _ := filepath.Rel(path.Join(os.Getenv("GOPATH"), "src"), lPath)
	logging.Logger.Println("1st: ", path.Join(os.Getenv("GOPATH"), "src"), " 2nd: ", loc)
	logging.Logger.Println(relPath)

	tempFolder := randStringRunes(10)
	tempLoc := path.Join(os.Getenv("GOPATH"), "src", tempFolder)
	logging.Logger.Println("temploc: ", tempLoc)
	// first copy the edited file over to the gopath so it can be ran
	//Check to ensure the directory does not exist
	if _, err := os.Stat(tempLoc); os.IsNotExist(err) {
		//Make the directory under resources with listener name
		os.Mkdir(tempLoc, 0755)
		defer os.RemoveAll(tempLoc)
	}

	copy(path.Join(lPath, lType+"_agent.go"), path.Join(tempLoc, lType+"_agent.go"))

	copyDep(path.Join(newGoDir, "src"), tempFolder, goos)

	//then make package changes
	context := build.Default
	context.GOOS = goos
	context.GOPATH = newGoDir
	context.CgoEnabled = false
	context.GOARCH = arch
	context.GOROOT = os.Getenv("GOROOT")

	encPkg := gobfuscate.ObfuscatePackageNames(newGoDir, buf, context)

	logging.Logger.Println("final encpgk location:", encPkg)

	//then string changes
	gobfuscate.ObfuscateStrings(newGoDir)

	//then function changes
	logging.Logger.Println("symbols next")
	gobfuscate.ObfuscateSymbols(newGoDir, buf, context)

	//then compile the new files
	if !preComp {
		//TODO BUILD OUT FOR MORE ARCH/TYPES
		command := []string{"build"}
		if goos == "windows" {
			command = append(command, `-ldflags=-s -w -H=windowsgui`)
		} else {
			command = append(command, `-ldflags=-s -w`)
		}
		command = append(command, "-trimpath")
		command = append(command, "-o")

		var filename string
		switch goos {
		case "windows":
			filename = lType + "Agent_Win_" + arch + "_Intel.exe"
		case "linux":
			filename = lType + "Agent_Lin_" + arch + "_Intel"
		case "darwin":
			filename = lType + "Agent_Mac_" + arch + "_Intel"
		case "android":
			filename = lType + "Agent_Android_" + arch + "_Arm"
			goos = "linux"
		}
		command = append(command, path.Join(lPath, filename))

		command = append(command, path.Join(encPkg, lType+"_agent.go"))

		compileBinary(goos, arch, command, cwd, newGoDir)
		msg := "{\"Key\": \"" + lName + "\", \"File\": \"" + filename + "\"}"
		outMsg := websockets.SendMessage{
			Type:         "Listener",
			FunctionName: "AgentCreate",
			Data:         msg,
			Success:      true,
		}
		logging.Logger.Println(outMsg)
		websockets.AlertUsers(outMsg)
	}

}

//PrepObfuscation pre-obfuscates all of the agents in order to save time
func PrepObfuscation(obfuscate bool) {
	if !obfuscate {
		logging.Logger.Println("Moving the files into position..")

		moveToGoPath()

		return
	}

	logging.Logger.Println("Starting obfuscation this can take some time...")

	preObfuscated = true

	//obfuscate them and put them into the right location

	//if not just move em
	/*
		Folders to move:
		/Agents
		/Lib

	*/

	/*need to obfuscate all the files without the final data in it..
	need to not compile them
	Need to keep them from being deleted
	Not everything has to be moved now that i own gopath fully
	Names would need to be recorded for me to references back too
	Could be held as an array to the main location for the 5 listeners
		TCP
		Pivot
		HTTPs
		Quic
		DNS


	*/

}

func moveToGoPath() {

	cwd, err := os.Getwd()
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	//Should know the exact gopath
	goPath := os.Getenv("GOPATH")
	logging.Logger.Println("GoPATH in moving is: ", goPath)
	if goPath == "" {
		goPath = build.Default.GOPATH
	}
	destPath := path.Join(goPath, "src", "github.com", "DeimosC2", "DeimosC2")

	for _, x := range []string{"agents", "lib"} {

		filepath.Walk(path.Join(cwd, x), func(fPath string, info os.FileInfo, err error) error {
			//logging.Logger.Println(fPath)
			relPath, err := filepath.Rel(path.Join(cwd), fPath)
			//logging.Logger.Println("REL PATH IS:", relPath)
			//logging.Logger.Println("FPATH IS: ", path.Join(destPath, relPath))
			if info.IsDir() {
				if _, err := os.Stat(path.Join(destPath, relPath)); os.IsNotExist(err) {
					//Make the directory under resources with listener name
					os.MkdirAll(path.Join(destPath, relPath), 0755)
				}
				return nil
			}
			copy(fPath, path.Join(destPath, relPath))
			return err
		})
	}

	//They will always be in the same place at this point so we update the main var
	fileLocations.doh = path.Join(destPath, "agents", "doh", "doh_agent.go")
	fileLocations.https = path.Join(destPath, "agents", "https", "https_agent.go")
	fileLocations.quic = path.Join(destPath, "agents", "quic", "quic_agent.go")
	fileLocations.tcp = path.Join(destPath, "agents", "tcp", "tcp_agent.go")

	logging.Logger.Println("Locations set:", fileLocations)

}

func randStringRunes(n int) string {
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
