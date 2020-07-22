package main

import "github.com/DeimosC2/DeimosC2/lib/logging"

//Listener
var ip = "127.0.0.1"
var port = "4153"

//This is the binary that we can use to execute our unsigned agent binary
var trustedBinary = "%userprofile%\\AppData\\Local\\Microsoft\\Teams\\Update.exe"

func main() {
	logging.Logger.Println("First  dropper")
}

func downloadAgent() {
	logging.Logger.Println("Here we will download the  agent")
}

func executeAgent() {
	logging.Logger.Println("Here we will execute the  agent")
}

func escalateUser() {
	logging.Logger.Println("Here we will try and  own the system")
}

func cleanUp() {
	logging.Logger.Println("Here we will cleanup the  dropper")
}
