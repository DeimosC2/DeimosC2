package logging

import (
	"log"
	"os"
	"path"
)

var (
	//Logger to log straight to the console
	Logger       = log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lshortfile)
	cmdlogger    *log.Logger
	modlogger    *log.Logger
	backuplogger *log.Logger
	//ErrorLogger is here to log your mistakes
	ErrorLogger   *log.Logger
	cmdHistory    *os.File
	modHistory    *os.File
	backupHistory *os.File
	errorHistory  *os.File
)

//InitLogger sets up the logging files for later use
func InitLogger() {
	cwd, err := os.Getwd()
	if err != nil {
		os.Exit(10)
	}
	cmdHistory, err = os.OpenFile(path.Join(cwd, "resources", "logs", "cmdhistory.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	modHistory, err = os.OpenFile(path.Join(cwd, "resources", "logs", "modhistory.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	backupHistory, err = os.OpenFile(path.Join(cwd, "resources", "logs", "backuphistory.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	errorHistory, err = os.OpenFile(path.Join(cwd, "resources", "logs", "errorhistory.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)

	cmdlogger = log.New(cmdHistory, "", log.Ldate|log.Ltime)
	modlogger = log.New(modHistory, "", log.Ldate|log.Ltime)
	backuplogger = log.New(modHistory, "", log.Ldate|log.Ltime)
	ErrorLogger = log.New(errorHistory, "", log.Ldate|log.Ltime|log.Lshortfile)
}

//TheRecovery is used to save the application from dying
func TheRecovery() {
	if err := recover(); err != nil {
		Logger.Println(err)
	}
}

//CMDLog is used to log user's commands
func CMDLog(data ...interface{}) {
	cmdlogger.Println(data...)
}

//ModLog logs users module usage
func ModLog(data ...interface{}) {
	modlogger.Println(data...)
}

//BackupLog logs users module usage
func BackupLog(data ...interface{}) {
	backuplogger.Println(data...)
}

//CloseLog will close the handle on log files when EndGame is called
func CloseLog() {
	cmdHistory.Close()
	modHistory.Close()
}
