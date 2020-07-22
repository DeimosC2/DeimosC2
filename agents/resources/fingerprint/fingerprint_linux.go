// +build linux

package fingerprint

import (
	"os"
	"os/exec"
	"strings"
)

//FingerPrint will get the version of the Operating System
func FingerPrint() (string, string, []string) {
	//Setting these higher as they will be in if/else statements due to checking for android
	var osType string
	var osVers string

	//First we need to check if the Linux system is Android or not
	if _, err := os.Stat("/system/build.prop"); err == nil {
		osType = "Android"
		// Using getprop ro.build.version.release to get version of Android
		cmd := exec.Command("getprop", "ro.build.version.release")
		out, err := cmd.CombinedOutput()
		if err != nil {
			osVers = err.Error()
		}
		osVers = strings.TrimSpace(string(out))
	} else if os.IsNotExist(err) {
		//Getting Distro name
		cmd := exec.Command("/bin/bash", "-c", "awk -F'=' '/^ID=/ {print $2}' /etc/os-release | tr -d '\"'")
		outType, err := cmd.CombinedOutput()
		if err != nil {
			osType = err.Error()
		}
		osType = string(outType)

		//Getting Distro Version
		cmd1 := exec.Command("/bin/bash", "-c", "awk -F'=' '/^VERSION_ID=/ {print $2}' /etc/os-release | tr -d '\"'")
		outVers, err := cmd1.CombinedOutput()
		if err != nil {
			osVers = err.Error()
		}
		osVers = string(outVers)

	} else {
		osType = "No Idea!"
		osVers = "Couldn't Get!"
	}

	//Future check for AV on Linux
	var av []string
	av = append(av, "null")

	return osType, osVers, av
}
