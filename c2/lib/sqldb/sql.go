package sqldb

import (
	"database/sql"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"

	//Import is blank because it's a driver
	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/DeimosC2/DeimosC2/c2/lib/validation"
	"github.com/DeimosC2/DeimosC2/c2/webserver/websockets"
	"github.com/DeimosC2/DeimosC2/lib/logging"
)

type adminStruct struct {
	Options []string
}

type users struct {
	UserID         string
	UserName       string
	LastLogin      string
	FailedAttempts string
	Admin          string
}

type loot struct {
	Agentkey string
	User     string
	Password string
	Hash     string
	Creds    string
	SSP      string
	Host     string
	Domain   string
}

type commentStruct struct {
	Comment      string
	User         string
	CreationTime string
}

var db *sql.DB

//ADD AGENT HEART BEAT TABLE WITH AGENT NAME AND 24HR TRACKER

//Initalize is run when the server spins up, it's used to verify the sqlite db or create it
func Initalize(filename string) {
	//Deletes any that already exists
	os.Remove(filename)

	OpenDB(filename)

	//Table contains (key, mfa, passlength)
	_, err := db.Exec("create table appsettings (key integer not null primary key, mfa bool, passlength int)")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	//Table contains (key, userid, username, password (hashed), lastlogin, number of failed attempts, mfa setup or not, google mfa secret, is admin or not)
	_, err = db.Exec("create table users (key integer not null primary key, userid text, username text, password text, lastlogin datetime, failedattempts integer, mfa bool, mfasecret text, admin integer, active integer)")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	//Table contains (key, listenerkey, listenername, type of listener, host of listener, bindport of listenery, end of life setting, pubkey of listener, privkey of listener, advanced options of listener, delay to be set in agent, jitter to be set in agent, agent eol, agent live hours, userid of who created it, and foreign key of userid)
	_, err = db.Exec("create table listeners (key integer not null primary key, listenerkey text, listenername text, type text, host text, bindport text, pubkey blob, privkey blob, advanced text, agentdelay text, agentjitter text, agenteol text, agentlivehours text , userid text, active integer, foreign key(userid) references users(userid))")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	//Table contains (key, agentkey, listenerkey, OS of victim, osType of victim, osVers of victim, av on victim machine, hostname of victim, username of victim, localip of victim, path of agent, shell1/2/3 are available shell types on victim, pid of agent, is the agent active, creation time, foreign key of listenerkey)
	_, err = db.Exec("create table agents (key integer not null primary key, agentkey text, agentname text, listenerkey text, os text, osType text, osVers text, av text, hostname text, username text, localip text, externalip text, path text, shell1 text, shell2 text, shell3 text, pid integer, isadmin bool, iselevated bool, active integer, creationtime datetime, lastcheckin datetime, foreign key(listenerkey) references listeners(listenerkey))")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	//Table contains (key, dropper name, type of dropper, userid of who generated the dropper, listenerkey, time it was generated, foreign key with userid and listener key)
	_, err = db.Exec("create table droppers (key integer not null primary key, droppername text, type text, userid text, listenerkey text, timegen datetime, foreign key(userid) references users(userid), foreign key(listenerkey) references listeners(listenerkey))")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	//Table contains (key, agentkey of where loot was gathered, user of loot, password, hash, credtype is type of cred (e.g. LSA), ssp, host of where cred was gained, domain of cred, timegen of when it was gained, linking agentkey table and userid as foreign keys to associate loot data)
	_, err = db.Exec("create table loot (key integer not null primary key, agentkey text, user text, password text, hash text, credtype text, ssp text, host text, domain text, timegen datetime, foreign key(agentkey) references agents(agentkey))")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	//Table contains (key, URL of victim, AuthToken for webshell, OS of victim, hostname of victim, username of victim, localip of victim, domain of victim, is webshell active, and creation date)
	_, err = db.Exec("create table webshells (key integer not null primary key, url text, authtoken text, webshellkey text, os text, hostname text, username text, localip text, domain text, active integer, creationtime datetime)")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	//Table containing (key, hour to backup, days to backup, status of backup or not)
	_, err = db.Exec("create table backups (key integer not null primary key, hour text, days text, status bool)")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	//Table containing (key, agentkey, username, comment, datetime)
	_, err = db.Exec("create table comments (key integer not null primary key, agentkey text, username text, comment text, creationtime datetime, foreign key(agentkey) references agents(agentkey))")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	//Setting default backups to off
	backupCMD, err := db.Prepare("INSERT INTO backups(hour, days, status) values(?, ?, ?)")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	backupCMD.Exec("null", "null", false)
}

///////////////////// Open and Close DB SQL Functions /////////////////////

//OpenDB is just to open the database and put it into the global variable
func OpenDB(filename string) {
	var err error
	db, err = sql.Open("sqlite3", filename)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
}

//CloseDB closes the db to ensure we can archive it in a zip folder
func CloseDB() bool {
	err := db.Close()
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
		return false
	}
	return true
}

///////////////////// App Settings SQL Functions /////////////////////

//InitAppSettings sets up the requirements for the users on the web app
func InitAppSettings(mfa bool, passLegnth int) bool {
	sqlCmd, err := db.Prepare("INSERT INTO appsettings(mfa, passlength) values(?, ?)")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
		return false
	}
	sqlCmd.Exec(mfa, passLegnth)
	return true
}

//appSettings is the API call to change app settings
func appSettings(mfa bool, passLength int) bool {
	sqlCmd, err := db.Prepare("UPDATE appsettings set mfa=?, passlength=?")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
		return false
	}
	sqlCmd.Exec(mfa, passLength)
	return true
}

//listAppSettings returns the app settings to the FE for admins to see
func listAppSettings() (bool, int) {
	var mfaSetting bool
	var passLegnth int
	db.QueryRow("SELECT mfa, passlength FROM appsettings").Scan(&mfaSetting, &passLegnth)

	return mfaSetting, passLegnth
}

///////////////////// User Auth SQL Functions /////////////////////

//hashs the password for the db
func hashPassword(password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	return string(hash)
}

//CheckPassword verifies that the password is correct
func CheckPassword(password string, hashedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err == nil {
		return true
	}
	return false
}

//FirstUser adds the first admin when server is started for the first time
func FirstUser(username string, clearPassword string) bool {
	newUserid := uuid.NewV4()
	hpass := hashPassword(clearPassword)
	sqlCmd, err := db.Prepare("insert into users(userid, username, password, lastlogin, failedattempts, admin, active) values(?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
		return false
	}
	sqlCmd.Exec(newUserid, username, hpass, time.Now(), 0, 1, 1)
	return true
}

//resetUser will force a reset a users password and/or MFA if MFA is true
func resetUser(userid string) bool {
	var mfa bool
	var sqlCmd *sql.Stmt

	err := db.QueryRow("SELECT mfa FROM appsettings").Scan(&mfa)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
		return false
	}

	if mfa {
		sqlCmd, err = db.Prepare("UPDATE users set mfa=?, lastlogin=? WHERE userid=?")
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
			return false
		}
		sqlCmd.Exec(false, nil, userid)
		return true
	}
	//If not MFA
	sqlCmd, err = db.Prepare("UPDATE users set lastlogin=? WHERE userid=?")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
		return false
	}
	sqlCmd.Exec(nil, userid)
	return true
}

//GetMFASecret gets the MFA secret for the requesting user
func GetMFASecret(userID string) string {
	var secret string
	err := db.QueryRow("SELECT mfasecret FROM users WHERE userid=?", userID).Scan(&secret)
	if err != nil {
		return err.Error()
	}
	return secret
}

//SetupMFA updates the users mfa and mfasecret fields for MFA authentication
func SetupMFA(userID string, secret string) bool {
	sqlCmd, err := db.Prepare("UPDATE users set mfa=?, mfasecret=? WHERE userid=?")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
		return false
	}
	sqlCmd.Exec(true, secret, userID)
	return true
}

//CheckMFA checks to see if a user already has a secret generated and stored
func CheckMFA(userID string) bool {
	var mfasecret string
	err := db.QueryRow("SELECT mfasecret FROM users WHERE userid=?", userID).Scan(&mfasecret)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
		return false
	}
	if mfasecret == "" {
		return false
	}
	return true
}

//AddUser adds a user for the front end
func AddUser(username string, clearPassword string, admin int) (bool, string) {
	var passLegnth int

	//Check to ensure username is unique
	rows, err := db.Query("SELECT username FROM users")
	if err != nil {
		return false, "Query to find username failed"
	}
	defer rows.Close()
	for rows.Next() {
		var userName string
		err = rows.Scan(&userName)
		if err != nil {
			return false, err.Error()
		}
		if userName == username {
			return false, "Can't have two users with the same name!"
		}
	}

	db.QueryRow("SELECT passlength FROM appsettings").Scan(&passLegnth)
	//Checks password length requirement to ensure we are meeting the standard set by the admin on startup
	if passLegnth > len(clearPassword) {
		return false, "Password does not meet required length!"
	}

	newUserid := uuid.NewV4()
	hpass := hashPassword(clearPassword)

	sqlCmd, err := db.Prepare("insert into users(userid, username, password, lastlogin, failedattempts, admin, active) values(?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
		return false, "Failed to Add User!"
	}
	sqlCmd.Exec(newUserid, username, hpass, nil, 0, admin, 1)
	return true, "User created!"
}

//Login checks the username and password, if they are correct then it returns true
func Login(user string, pass string) (bool, string, bool, bool, bool, bool) {
	var hashedPassword string
	var userid string
	var admin int
	var mfasettings bool
	var mfaconfigured sql.NullBool
	var lastlogin sql.NullTime
	err := db.QueryRow("SELECT password, userid, lastlogin, mfa, admin FROM users WHERE username=?", user).Scan(&hashedPassword, &userid, &lastlogin, &mfaconfigured, &admin)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
		return false, user, false, false, false, false
	}

	//If auth successful we need to set lastlogin to be current time
	sqlCmdLogin, err := db.Prepare("UPDATE users set lastlogin=? WHERE username=?")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	//Check how many failed attempts are present
	var count int
	err = db.QueryRow("SELECT failedattempts FROM users WHERE username=?", user).Scan(&count)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	//If auth fails we need to increment failed attempts
	sqlCmdFailedAttempts, err := db.Prepare("UPDATE users set failedattempts=? WHERE username=?")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	//Check if MFA is required on the system
	err = db.QueryRow("SELECT mfa FROM appsettings").Scan(&mfasettings)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	//Checking to ensure password and hash equal and if so then move on the validate if first time or not
	goodPass := CheckPassword(pass, hashedPassword)
	if admin == 1 {
		if goodPass {
			if !lastlogin.Valid {
				sqlCmdFailedAttempts.Exec(0, user)
				return goodPass, userid, true, true, mfasettings, mfaconfigured.Bool
			}
			sqlCmdLogin.Exec(time.Now(), user)
			sqlCmdFailedAttempts.Exec(0, user)
			return goodPass, userid, true, false, mfasettings, mfaconfigured.Bool
		} else if !goodPass {
			count++
			sqlCmdFailedAttempts.Exec(count, user)
			return false, user, false, false, mfasettings, mfaconfigured.Bool
		}
	} else {
		if goodPass {
			if !lastlogin.Valid {
				sqlCmdFailedAttempts.Exec(0, user)
				return goodPass, userid, false, true, mfasettings, mfaconfigured.Bool
			}
			sqlCmdLogin.Exec(time.Now(), user)
			sqlCmdFailedAttempts.Exec(0, user)
			return goodPass, userid, false, false, mfasettings, mfaconfigured.Bool
		} else if !goodPass {
			count++
			sqlCmdFailedAttempts.Exec(count, user)
			return false, user, false, false, mfasettings, mfaconfigured.Bool
		}
	}
	return false, "", false, false, false, false
}

//ChangeUserPassword will force the user to change their password and update lastlogin
func ChangeUserPassword(userid string, newdata string, oldpass string) (bool, string) {
	//Check to ensure old password is correct for the user
	var hashedPassword string
	err := db.QueryRow("SELECT password FROM users WHERE userid=?", userid).Scan(&hashedPassword)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	goodPass := CheckPassword(oldpass, hashedPassword)
	//If old pass is correct change password
	if goodPass {
		var passLegnth int
		db.QueryRow("SELECT passlength FROM appsettings").Scan(&passLegnth)
		//Checks password length requirement to ensure we are meeting the standard set by the admin on startup
		if passLegnth > len(newdata) {
			return false, "New Password Not Meeting Length Requirements!"
		}
		newdata = hashPassword(newdata)
		sqlCmd, err := db.Prepare("update users set password = ? where userid = ?;")
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}

		sqlCmd.Exec(newdata, userid)

		//Set lastlogin to be current time
		sqlCmdLogin, err := db.Prepare("UPDATE users set lastlogin=? WHERE userid=?")
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}
		sqlCmdLogin.Exec(time.Now(), userid)
		return true, "Changed Password"
	}
	return false, "Something went wrong!"
}

//editUserData will allow users to change their password
func editUserData(userid string, newUsername string, newPassword string, admin int) bool {

	var sqlCmd *sql.Stmt
	var err error

	//If new password is not empty then set the new password
	if newPassword != "" {
		newdata := hashPassword(newPassword)
		sqlCmd, err = db.Prepare("update users set password = ? where userid = ?;")
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
			return false
		}
		sqlCmd.Exec(newdata, userid)
	}

	//If the new username is not empty then set it
	if newUsername != "" {
		sqlCmd, err = db.Prepare("update users set username = ? where userid = ?;")
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
			return false
		}
		sqlCmd.Exec(newUsername, userid)
	}

	//If admin is 1 then make user admin
	if admin == 1 {
		sqlCmd, err = db.Prepare("update users set admin = ? where userid = ?;")
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
			return false
		}
		sqlCmd.Exec(admin, userid)
	}

	//If admin is 0 then make them non-admin
	if admin == 0 {
		sqlCmd, err = db.Prepare("update users set admin = ? where userid = ?;")
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
			return false
		}
		sqlCmd.Exec(admin, userid)
	}
	return true
}

func deleteUser(userid string) bool {
	//Changes the active status of the user to 0 but keeps record of them being on the app
	sqlCmd, err := db.Prepare("UPDATE users SET active=0 WHERE userid=$1;")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
		return false
	}
	sqlCmd.Exec(userid)
	return true
}

//List users that are active in the database
func listUsers() (bool, string) {
	var allUsers []users
	var lastLoginCheck sql.NullTime
	rows, err := db.Query("SELECT userid, username, lastlogin, failedattempts, admin FROM users WHERE active=1")
	if err != nil {
		return false, err.Error()
	}
	defer rows.Close()
	var userList users
	for rows.Next() {
		err = rows.Scan(&userList.UserID, &userList.UserName, &lastLoginCheck, &userList.FailedAttempts, &userList.Admin)
		if err != nil {
			return false, err.Error()
		}
		if !lastLoginCheck.Valid {
			userList.LastLogin = "Null"
		} else {
			userList.LastLogin = lastLoginCheck.Time.String()
		}
		allUsers = append(allUsers, userList)
	}
	jsonMsg, _ := json.Marshal(allUsers)
	logging.Logger.Println(string(jsonMsg))
	return true, string(jsonMsg)
}

///////////////////// Agent SQL Functions /////////////////////

//AddAgent adds an agent to the database
//Might want to change this so it just passes a struct but i dont think it really matters from a performance standpoint.. This can be applied to all of the add functions within this package
func AddAgent(agentkey string, agentname string, os string, osType string, osVers string, av []byte, hostname string, username string, localip string, externalip string, path string, shell1 string, shell2 string, shell3 string, pid int, isAdmin bool, isElevated bool, active int, listenerkey string) {
	sqlCmd, err := db.Prepare("insert into agents(agentkey, agentname, listenerkey, os, osType, osVers, av, hostname, username, localip, externalip, path, shell1, shell2, shell3, pid, isadmin, iselevated, active, creationtime, lastcheckin) values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	sqlCmd.Exec(agentkey, agentname, listenerkey, os, osType, osVers, av, hostname, username, localip, externalip, path, shell1, shell2, shell3, pid, isAdmin, isElevated, active, time.Now(), time.Now())
}

//AgentCheckin updates the last checkin time for the agent
func AgentCheckin(agentName string) {
	_, err := db.Exec("update agents set lastcheckin = ? where agentname = ?", time.Now(), agentName)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

}

//DeleteAgent switches the active bit from 1 to 0 when called
func DeleteAgent(agentkey string) {
	logging.Logger.Println("deleting the agent: ", agentkey)
	rows, err := db.Exec("update agents set active=0 where agentkey = ?", agentkey)

	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	i, err := rows.RowsAffected()
	logging.Logger.Println("Rows affected by deletion: ", i, err)
}

//removeAgentsByDeletedListener will remove any agents attached to a deleted listener so that there are no errors bringing it back up
func removeAgentsByDeletedListener(listenerKey string) {
	logging.Logger.Println("deleting agents")
	rows, err := db.Query("SELECT agentkey FROM agents WHERE listenerkey=$1", listenerKey)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	var toDelete []string
	for rows.Next() {
		var agentkey string
		err = rows.Scan(&agentkey)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}
		logging.Logger.Println("Agent Key is:", agentkey)
		toDelete = append(toDelete, agentkey)
	}
	rows.Close()
	for _, y := range toDelete {
		DeleteAgent(y)
	}
}

//AgentOSTypes returns the os for all agents in the DB
func AgentOSTypes() string {
	var osTypes string
	var windows int
	var linux int
	var macOS int
	var android int
	var iOS int
	rows, err := db.Query("SELECT os FROM agents WHERE active = 1")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	defer rows.Close()
	for rows.Next() {
		var os string
		err = rows.Scan(&os)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}
		switch {
		case os == "windows":
			windows++
		case os == "linux":
			linux++
		case os == "darwin":
			macOS++
		case os == "android":
			android++
		case os == "ios":
			iOS++
		}

	}
	osTypes = "{\"Windows\":" + strconv.Itoa(windows) + ",\"Linux\":" + strconv.Itoa(linux) + ",\"Darwin\":" + strconv.Itoa(macOS) + ",\"Android\":" + strconv.Itoa(android) + ",\"iOS\":" + strconv.Itoa(iOS) + "}"
	return osTypes
}

//AgentByListener returns the listener for all agents in the DB
func AgentByListener() string {
	var allLKeys []string
	listeners := make(map[string]int) //need to fill with all agents

	//Gets all of the listeners keys that agents are attached too
	rows, err := db.Query("SELECT listenerkey FROM agents WHERE active = 1")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	//Goes through them
	defer rows.Close()
	for rows.Next() {
		var listenerkey string
		err = rows.Scan(&listenerkey)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}
		allLKeys = append(allLKeys, listenerkey)
	}
	//At this point all keys holds all of the listener keys

	//Here we need to get all of the listners and then add up how many have agents attached
	rows, err = db.Query("SELECT listenerkey FROM listeners")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	defer rows.Close()
	for rows.Next() {
		var listenerkey string
		err = rows.Scan(&listenerkey)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}
		listeners[listenerkey] = 0
	}

	for _, word := range allLKeys {
		_, ok := listeners[word]
		if ok {
			listeners[word]++
		}
	}

	var data string
	data = "{"
	for a, b := range listeners {
		data = data + "\"" + a + "\":" + strconv.Itoa(b) + ","
	}
	data = strings.TrimSuffix(data, ",")
	data = data + "}"

	return data
}

//AgentTimeline returns the time for all agents in the DB
func AgentTimeline() []string {
	var allStartTimes []string
	rows, err := db.Query("SELECT creationtime FROM agents")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	defer rows.Close()
	for rows.Next() {
		var creationTime string
		err = rows.Scan(&creationTime)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}
		allStartTimes = append(allStartTimes, creationTime)
	}
	return allStartTimes
}

//GetAgentData returns the data needed to reinit agents into memory
func GetAgentData() *sql.Rows {
	rows, err := db.Query("SELECT agentkey, agentname, listenerkey, os, osType, osVers, av, hostname, username, localip, externalip, path, shell1, shell2, shell3, pid, isadmin, iselevated, lastcheckin FROM agents WHERE active=1")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	return rows
}

//SetAgentName sets the agent name in the DB
func SetAgentName(agentKey string, agentName string) (string, string) {
	sqlCmd, err := db.Prepare("UPDATE agents set agentname=? WHERE agentkey=?")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
		return "Failed", err.Error()
	}
	sqlCmd.Exec(agentName, agentKey)
	return agentKey, agentName
}

//GetAgentPivotData returns some data about the agents for the pivot graph
func GetAgentPivotData() *sql.Rows {
	rows, err := db.Query("SELECT agentkey, agentname, listenerkey, os, iselevated, hostname, username, localip FROM agents WHERE active = 1")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	return rows
}

///////////////////// Listener SQL Functions /////////////////////

//AddListener adds a listener to the db
func AddListener(key string, name string, ltype string, host string, bindport string, pubkey []byte, privkey []byte, advanced string, agentdelay string, agentjitter string, agenteol string, agentlivehours string, userid string) {
	sqlCmd, err := db.Prepare("insert into listeners(listenerkey, listenername, type, host, bindport, pubkey, privkey, advanced, agentdelay, agentjitter, agenteol, agentlivehours, userid, active) values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	sqlCmd.Exec(key, name, ltype, host, bindport, pubkey, privkey, advanced, agentdelay, agentjitter, agenteol, agentlivehours, userid, 1)
}

//EditListener changes the listener's settings to the new user supplied ones
func EditListener(key string, name string, ltype string, host string, bindport string, pubkey []byte, privkey []byte, advanced string, agentdelay string, agentjitter string, agenteol string, agentlivehours string, userid string) {
	sqlCmd, err := db.Prepare("update listeners set listenername= ?, type=?, host=?, bindport=?, pubkey=?, privkey=?, advanced=?, agentdelay=?, agentjitter=?, agenteol=?, agentlivehours=?, userid=?, active=? where listenerkey=?")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	sqlCmd.Exec(name, ltype, host, bindport, pubkey, privkey, advanced, agentdelay, agentjitter, agenteol, agentlivehours, userid, 1, key)
}

//ListenerExists returns true if the listener exists
func ListenerExists(name string) bool {
	var exists bool
	err := db.QueryRow("SELECT id FROM listeners WHERE name=?", name).Scan(&exists)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	return exists
}

//GetListenerPrivateKey returns the private key for the listener
func GetListenerPrivateKey(key string) string {
	var privKey string
	err := db.QueryRow("SELECT privkey FROM listeners WHERE listenerkey=?", key).Scan(&privKey)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	return privKey
}

//GetListeners gets everything on listeners out of the database and returns it
func GetListeners() *sql.Rows {
	rows, err := db.Query("SELECT type, listenername, host, bindport, listenerkey, pubkey, privkey, advanced, agentdelay, agentjitter, agenteol, agentlivehours FROM listeners WHERE active=1")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	return rows
}

//GetListenerKeys returns a slice of all listeners
func GetListenerKeys() ([]string, map[string]string, map[string]string, map[string]string) {
	rows, err := db.Query("SELECT listenerkey, type, bindport, listenername FROM listeners")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	defer rows.Close()
	var listeners []string
	types := make(map[string]string)
	ports := make(map[string]string)
	names := make(map[string]string)
	for rows.Next() {
		var listenerkey string
		var tmpType string
		var tmpPort string
		var listenerName string
		err = rows.Scan(&listenerkey, &tmpType, &tmpPort, &listenerName)
		listeners = append(listeners, listenerkey)
		types[listenerkey] = tmpType
		ports[listenerkey] = tmpPort
		names[listenerkey] = listenerName
	}

	return listeners, types, ports, names
}

//RemoveListener changes to active
func RemoveListener(lName string) {
	rows, err := db.Exec("update listeners set active=0 where listenerkey = ?", lName)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	} else {
		i, err := rows.RowsAffected()
		logging.Logger.Println("Rows affected by deletion: ", i, err)
		removeAgentsByDeletedListener(lName)
	}
}

//CheckListener checks to ensure listener exists for moving laterally
func CheckListener(lName string) (bool, string) {
	var exists bool
	err := db.QueryRow("SELECT listenerkey FROM listeners WHERE listenerkey=?", lName).Scan(&exists)
	switch {
	case err == sql.ErrNoRows:
		return false, "That listener doesn't exists! You can't choose one from the future!!"
	case err != nil:
		logging.ErrorLogger.Println(err.Error())
	default:
		var listType string
		err := db.QueryRow("SELECT type FROM listeners WHERE listenerkey=?", lName).Scan(&listType)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}
		return true, listType
	}
	return false, "Something broke so go ahead and go home!"
}

///////////////////// Loot SQL Functions /////////////////////

//AddLoot adds loot to the db
func AddLoot(agentkey string, user string, password string, hash string, credtype string, ssp string, host string, domain string, isWebShell bool) {
	logging.Logger.Println("Data sent to add loot is: ", agentkey, user, password, hash, credtype, ssp, host, domain, isWebShell)
	var hostIP string
	if isWebShell == false {
		err := db.QueryRow("SELECT localip FROM agents WHERE agentkey=?", agentkey).Scan(&hostIP)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}
	} else {
		err := db.QueryRow("SELECT localip FROM webshells WHERE webshellkey=?", agentkey).Scan(&hostIP)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}
	}

	sqlCmd, err := db.Prepare("insert into loot (agentkey, user, password, hash, credtype, ssp, host, domain, timegen) values(?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	sqlCmd.Exec(agentkey, user, password, hash, credtype, ssp, host, domain, time.Now())
}

//EditPassLoot edits loot entry to add a password
func EditPassLoot(password string, hash string) (bool, int) {
	var sqlCmd *sql.Stmt
	var err error

	sqlCmd, err = db.Prepare("UPDATE loot set password = ? WHERE hash = ?;")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
		return false, 0
	}

	r, err := sqlCmd.Exec(password, hash)
	count, err := r.RowsAffected()
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	return true, int(count)
}

//ListAllLoot will return all loot from the database
func ListAllLoot() string {
	var allLoot []loot
	rows, err := db.Query("SELECT agentkey, user, password, hash, credtype, ssp, host, domain FROM loot")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	defer rows.Close()
	for rows.Next() {
		var lootLists loot
		err = rows.Scan(&lootLists.Agentkey, &lootLists.User, &lootLists.Password, &lootLists.Hash, &lootLists.Creds, &lootLists.SSP, &lootLists.Host, &lootLists.Domain)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}
		allLoot = append(allLoot, lootLists)
	}
	jsonMsg, _ := json.Marshal(allLoot)
	return string(jsonMsg)
}

//ListLoot will return all loot from the database
func ListLoot(agentkey string) string {
	var allLoot []loot
	rows, err := db.Query("SELECT agentkey, user, password, hash, credtype, ssp, host, domain FROM loot WHERE agentkey=?", agentkey)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	defer rows.Close()
	var lootLists loot
	for rows.Next() {
		err = rows.Scan(&lootLists.Agentkey, &lootLists.User, &lootLists.Password, &lootLists.Hash, &lootLists.Creds, &lootLists.SSP, &lootLists.Host, &lootLists.Domain)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}
		allLoot = append(allLoot, lootLists)
	}
	jsonMsg, _ := json.Marshal(allLoot)
	return string(jsonMsg)
}

///////////////////// Dropper SQL Functions /////////////////////

//AddDropper adds a dropper to the db
func AddDropper(name string, dtype string, userid string, lkey string, timegen time.Time) {
	sqlCmd, err := db.Prepare("insert into droppers(droppername, type, userid, listenerkey, timegen, values(?, ?, ?, ?, ?)")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	sqlCmd.Exec(name, dtype, userid, lkey, timegen)
}

///////////////////// Webshell SQL Functions /////////////////////

//AddWebshell will add an initalized webshell into the database
func AddWebshell(url string, authToken string, webkey string, os string, hostname string, username string, localIP string, domain string) {
	sqlCmd, err := db.Prepare("insert into webshells(url, authtoken, webshellkey, os, hostname, username, localip, domain, active, creationtime) values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	sqlCmd.Exec(url, authToken, webkey, os, hostname, username, localIP, domain, 1, time.Now())
}

//ListWebShell will list all the webshells existing in the database
func ListWebShell() *sql.Rows {
	rows, err := db.Query("SELECT url, authtoken, webshellkey, os, hostname, username, localip, domain FROM webshells WHERE active=1")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	return rows
}

//WebShellDeactivate will flip the active bit from 1 to 0 when delete WebShell is called
func WebShellDeactivate(name string) {
	rows, err := db.Exec("UPDATE webshells SET active=0 WHERE webshellkey=", name)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	} else {
		i, err := rows.RowsAffected()
		logging.Logger.Println("Rows effected by deleteing webshell: ", i, err)
	}
}

///////////////////// Archive SQL Functions /////////////////////

//CheckBackup checks the schedule of when a backup should run
func CheckBackup() (bool, string, string) {
	var day string
	var status bool
	var hour string
	var days []string
	//Query for column of current day
	//place value in day variable and grab time and status
	rows, err := db.Query("SELECT hour, days, status FROM backups")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	defer rows.Close()
	for rows.Next() {
		err = rows.Scan(&hour, &day, &status)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}
		json.Unmarshal([]byte(day), &days)
	}
	currentDay := time.Now().Weekday().String()
	for _, cday := range days {
		if strings.Contains(strings.ToLower(currentDay), strings.ToLower(cday)) {
			return status, cday, hour
		}
	}
	return false, "", ""
}

//SetSchedule sets the schedule for when a backup should run
func SetSchedule(hour string, days []byte, status bool) bool {
	sqlCmd, err := db.Prepare("UPDATE backups set hour=?, days=?, status=?")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
		return false
	}
	sqlCmd.Exec(hour, days, status)
	return true
}

//listBackupSchedule pulls current schedule set
func listBackupSchedule() []string {
	var listSettings []string
	var days []string
	rows, err := db.Query("SELECT hour, days, status FROM backups")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	defer rows.Close()
	for rows.Next() {
		var hour string
		var day string
		var status string
		err = rows.Scan(&hour, &day, &status)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}
		json.Unmarshal([]byte(day), &days)
		listSettings = append(listSettings, hour)
		listSettings = append(listSettings, days...)
		listSettings = append(listSettings, status)
	}
	return listSettings
}

///////////////////// User Comments SQL Functions /////////////////////

//AddComment will add the user comment per the agent they are commenting on
func AddComment(agentKey string, comment string, username string) (bool, string, string) {
	var agentExist string
	err := db.QueryRow("SELECT agentkey FROM agents WHERE agentkey=?", agentKey).Scan(&agentExist)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
		return false, "Agent doesn't Exist", agentKey
	}

	sqlCmd, err := db.Prepare("insert into comments(agentKey, comment, username, creationtime) values(?, ?, ?, ?)")
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
		return false, err.Error(), agentKey
	}
	sqlCmd.Exec(agentKey, comment, username, time.Now())
	return true, "Comment Added", agentKey
}

//ListComments will get all comments for that specific agent
func ListComments(agentKey string) (string, string) {
	var allComments []commentStruct
	rows, err := db.Query("SELECT comment, username, creationtime from comments WHERE agentkey=?", agentKey)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	defer rows.Close()
	for rows.Next() {
		var commentLists commentStruct
		err = rows.Scan(&commentLists.Comment, &commentLists.User, &commentLists.CreationTime)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}
		allComments = append(allComments, commentLists)
	}
	jsonMsg, _ := json.Marshal(allComments)
	return string(jsonMsg), agentKey
}

//ParseSocket parses calls to make DB edits from the frontend
func ParseSocket(fname string, data interface{}, ws *websocket.Conn, admin bool, userid string) {
	//API's that don't take in data from interface
	switch fname {
	//Admin return list of all users on system
	case "ListUsers":
		if admin {
			success, rData := listUsers()
			outMsg := websockets.SendMessage{
				Type:         "Admin",
				FunctionName: "ListUsers",
				Data:         rData,
				Success:      success,
			}
			websockets.AlertSingleUser(outMsg, ws)
			return
		}
		return
	case "ListAppSettings":
		if admin {
			//Getting app settings
			mfa, passlength := listAppSettings()
			//Converting those settings to string
			passLengthString := strconv.Itoa(passlength)
			mfaString := strconv.FormatBool(mfa)
			//Making output into JSON for the FE to parse
			output := "{\"MFASetting\":\"" + mfaString + "\", \"PassLength\": [\"" + passLengthString + "\"]}"
			outMsg := websockets.SendMessage{
				Type:         "Admin",
				FunctionName: "ListAppSettings",
				Data:         output,
				Success:      true,
			}
			websockets.AlertSingleUser(outMsg, ws)
			return
		}
		return
	case "ListBackupSchedule":
		if admin {
			rData := listBackupSchedule()
			outMsg := websockets.SendMessage{
				Type:         "Admin",
				FunctionName: "ListBackupSchedule",
				Data:         strings.Join(rData, ", "),
				Success:      true,
			}
			websockets.AlertSingleUser(outMsg, ws)
			return
		}
		return
	case "EditUser":
		if admin {
			//Validate data has key UserID, username, and password for this API call
			m := data.(map[string]interface{})
			if !validation.ValidateMapAlert(m, []string{"UserID", "username", "password", "admin"}, ws) {
				return
			}
			//Validate that the user is either 1 or else 0 to ensure users can't try and put 3 or some other strange number in this
			var admin int
			if m["admin"].(string) == "1" {
				admin = 1
			} else {
				admin = 0
			}
			success := editUserData(m["UserID"].(string), m["username"].(string), m["password"].(string), admin)
			outMsg := websockets.SendMessage{
				Type:         "Admin",
				FunctionName: "EditUser",
				Data:         "",
				Success:      success,
			}
			websockets.AlertSingleUser(outMsg, ws)
			return
		}
		return
	}

	//Validate data has key Options for the remaining API calls
	m := data.(map[string]interface{})
	if !validation.ValidateMapAlert(m, []string{"Options"}, ws) {
		return
	}

	var args []string
	switch val := m["Options"].(type) {
	case []interface{}:
		for _, x := range val {
			logging.Logger.Println(x)
			args = append(args, x.(string))
		}
	}
	options := adminStruct{
		Options: args,
	}

	//For each of these check to see if admin is required and then make calls per their access rights
	switch fname {
	case "AddUser":
		if admin {
			i, _ := strconv.Atoi(options.Options[2])
			//Pass blank string at the end of AddUser for blank secret
			success, result := AddUser(options.Options[0], options.Options[1], i)
			outMsg := websockets.SendMessage{
				Type:         "Admin",
				FunctionName: "AddUser",
				Data:         result,
				Success:      success,
			}
			logging.Logger.Println("Adding users:", outMsg)
			websockets.AlertSingleUser(outMsg, ws)
		}
	case "DeleteUser":
		if admin {
			success := deleteUser(options.Options[0])
			outMsg := websockets.SendMessage{
				Type:         "Admin",
				FunctionName: "DeleteUser",
				Data:         "",
				Success:      success,
			}
			websockets.AlertSingleUser(outMsg, ws)
		}
	case "AppSettings":
		if admin {
			mfaValue, _ := strconv.ParseBool(options.Options[0])
			passValue, _ := strconv.Atoi(options.Options[1])
			success := appSettings(mfaValue, passValue)
			outMsg := websockets.SendMessage{
				Type:         "Admin",
				FunctionName: "AppSettings",
				Data:         "",
				Success:      success,
			}
			websockets.AlertSingleUser(outMsg, ws)
		}
	case "ResetUser":
		if admin {
			success := resetUser(options.Options[0])
			outMsg := websockets.SendMessage{
				Type:         "Admin",
				FunctionName: "ResetUser",
				Data:         "",
				Success:      success,
			}
			websockets.AlertSingleUser(outMsg, ws)
		}
	}
}
