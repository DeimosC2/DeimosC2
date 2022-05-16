package webserver

import (
	"crypto/tls"
	"encoding/gob"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/gorilla/websocket"

	"github.com/DeimosC2/DeimosC2/c2/agents"
	"github.com/DeimosC2/DeimosC2/c2/lib"
	"github.com/DeimosC2/DeimosC2/c2/lib/archive"
	"github.com/DeimosC2/DeimosC2/c2/lib/sqldb"
	"github.com/DeimosC2/DeimosC2/c2/lib/validation"
	"github.com/DeimosC2/DeimosC2/c2/loot"
	"github.com/DeimosC2/DeimosC2/c2/webserver/mfa"
	"github.com/DeimosC2/DeimosC2/c2/webserver/websockets"
	"github.com/DeimosC2/DeimosC2/c2/webshells"
	"github.com/DeimosC2/DeimosC2/lib/logging"
)

var store *sessions.CookieStore

var serverConfig Config

//Message defines our message object
type Message struct {
	Type         string      `json:"message"`      //Holds the type of message
	FunctionName string      `json:"functionname"` //Holds the function names
	Data         interface{} `json:"data"`         //Holds the rest of the json data to be passed around
}

//User holds basic data on users for cookies
type User struct {
	UserID         string `json:"userid"`         //UUID for the DB
	Username       string `json:"username"`       //Username
	Authenticated  bool   `json:"authenticated"`  //Authed or not
	Admin          bool   `json:"admin"`          //If the user is an Admin or not
	ChangePassword bool   `json:"changepassword"` //Does the user need to change their password
	MFASetup       bool   `json:"mfasetup"`       //Check to see if MFA is set or not for user if it is required
	MFA            bool   `json:"mfa"`            //Check to see if they need to be prompted for MFA
	MFASuccess     bool   `json:"mfasuccess"`     //Did user pass MFA
}

//loginForm contians the POST data fields required to login
type loginForm struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

//setupForm is for first time setup of the C2 Server
type setupForm struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	MFA        bool   `json:"mfa"`
	PassLength int    `json:"passlength"`
}

//changePassword will contain the POST data fields to facilitate password changes
type changePassword struct {
	OldPass string `json:"oldpass"`
	NewPass string `json:"newpass"`
}

//Config holds info on the server configuration
type Config struct {
	DbFile        string //Database Filename
	Cert          string //Cert for the https server
	Key           string //Key for the https server
	WebserverPort string //Port to run the server on
	Setup         bool   //If true then run initial setup
}

//mfaForm holds the token value that will be posted to the BE
type mfaForm struct {
	Token string //Token for the MFA
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func handleConnections(w http.ResponseWriter, r *http.Request) {
	// Upgrade initial GET request to a websocket
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	} else if ws != nil {
		logging.Logger.Println("Client connected: \n", ws.RemoteAddr())
	}

	session, _ := store.Get(r, "Operator")
	val := session.Values["User"]
	logging.Logger.Println(val)
	uID := User{}
	uID, ok := val.(User)
	//If not authed kill
	if !ok || !uID.Authenticated {
		msg := websockets.SendMessage{
			Type:         "Cookie",
			FunctionName: "",
			Data:         "",
			Success:      false,
		}
		websockets.AlertSingleUser(msg, ws)
		cleanupSockets(ws)
	} else {
		// Make sure we close the connection when the function returns
		defer cleanupSockets(ws)
	}

	// Register our new client
	newClient := websockets.Client{
		Alive: true,
	}
	websockets.AllClients.Mutex.Lock()
	websockets.AllClients.List[ws] = &newClient
	websockets.AllClients.Mutex.Unlock()
	for {
		var msg Message
		// Read in a new message as JSON and map it to a Message object
		err = ws.ReadJSON(&msg)
		logging.Logger.Println("Full MSG is:", msg)
		if err != nil {
			logging.ErrorLogger.Println("HandleConections: ", err.Error())
			if e, ok := err.(*json.SyntaxError); ok {
				log.Printf("syntax error at byte offset %d", e.Offset)
			}
			cleanupSockets(ws)
			break
		}
		logging.Logger.Println("handleConnections::msg: \n", msg)
		if uID.ChangePassword {
			msg := websockets.SendMessage{
				Type:         "changepassword",
				FunctionName: "",
				Data:         "",
				Success:      true,
			}
			websockets.AlertSingleUser(msg, ws)
		} else if uID.MFASetup && !uID.MFA {
			//If MFA is set to true in AppSettings table and the user has never setup MFA before
			msg := websockets.SendMessage{
				Type:         "mfa_setup_required",
				FunctionName: "",
				Data:         "",
				Success:      true,
			}
			websockets.AlertSingleUser(msg, ws)
			//Sending userID, websocket
			mfaGenerate(uID.UserID, ws)
		} else if uID.MFASetup && uID.MFA && !uID.MFASuccess {
			msg := websockets.SendMessage{
				Type:         "mfa_required",
				FunctionName: "",
				Data:         "",
				Success:      true,
			}
			websockets.AlertSingleUser(msg, ws)
		} else if !uID.MFASetup || uID.MFASuccess { //If no MFA is required or MFA was successful
			//Send user info to FE
			data := "{\"userid\":\"" + uID.UserID + "\", \"username\": \"" + uID.Username + "\", \"admin\": \"" + strconv.FormatBool(uID.Admin) + "\"}"
			output := websockets.SendMessage{
				Type:         "user",
				FunctionName: "info",
				Data:         data,
				Success:      true,
			}
			websockets.AlertSingleUser(output, ws)
			//Checking msg.Type for API calls
			switch msg.Type {
			case "listener":
				logging.Logger.Println("Total MSG is: ", msg)
				lib.ParseSocket(msg.FunctionName, msg.Data, ws, uID.UserID, uID.Username)
			case "agent":
				agents.ParseSocket(msg.FunctionName, msg.Data, ws, uID.UserID, uID.Username)
			case "register":
				if msg.FunctionName == "agent" {
					m := msg.Data.(map[string]interface{})
					if !validation.ValidateMapAlert(m, []string{"agentkey"}, ws) {
						break
					}
					websockets.RegisterAgent(ws, m["agentkey"].(string))
				}
			case "deregister":
				if msg.FunctionName == "agent" {
					m := msg.Data.(map[string]interface{})
					if !validation.ValidateMapAlert(m, []string{"agentkey"}, ws) {
						break
					}
					websockets.DeregisterAgent(ws, m["agentkey"].(string))
				}
			case "metrics":
				dashparse(msg.FunctionName, msg.Data, ws)
			case "webShell":
				webshells.ParseSocket(msg.FunctionName, msg.Data, ws)
			case "admin":
				sqldb.ParseSocket(msg.FunctionName, msg.Data, ws, uID.Admin, uID.UserID)
			case "loot":
				loot.ParseSocket(msg.FunctionName, msg.Data, ws)
			case "archive":
				//Checks if user is admin before allowing this API to run
				if uID.Admin {
					archive.ParseSocket(msg.FunctionName, msg.Data, ws)
				} else {
					msg := websockets.SendMessage{
						Type:         "error",
						FunctionName: "",
						Data:         "Unauthorized Access. Nice Try!",
						Success:      false,
					}
					websockets.AlertSingleUser(msg, ws)
				}
			}
		}
	}
}

//Cleans up the closed sockets from the map
func cleanupSockets(ws *websocket.Conn) {
	websockets.AllClients.Mutex.Lock()
	defer websockets.AllClients.Mutex.Unlock()
	delete(websockets.AllClients.List, ws)
	ws.Close()
}

//RunServer starts the webserver
func RunServer(c Config) {
	serverConfig = c

	authKey := securecookie.GenerateRandomKey(32)
	encryptionKey := securecookie.GenerateRandomKey(32)

	store = sessions.NewCookieStore(
		authKey,
		encryptionKey,
	)

	store.Options = &sessions.Options{
		MaxAge:   86400 * 1, //1 day
		HttpOnly: false,
	}

	gob.Register(User{})

	cwd, err := os.Getwd()
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	static := path.Join(cwd, "resources", "frontend", "static")
	frontendConfig := path.Join(cwd, "resources", "frontend")

	router := mux.NewRouter()

	//Serve Web Socket
	router.HandleFunc("/ws", handleConnections)

	// Serve static assets directly.
	router.PathPrefix("/js").Handler(http.FileServer(http.Dir(static)))
	router.PathPrefix("/css").Handler(http.FileServer(http.Dir(static)))
	router.PathPrefix("/fonts").Handler(http.FileServer(http.Dir(static)))
	router.PathPrefix("/img").Handler(http.FileServer(http.Dir(static)))
	router.PathPrefix("/config").Handler(http.FileServer(http.Dir(frontendConfig)))
	router.PathPrefix("/listenerresources").HandlerFunc(protectedFiles(path.Join(cwd, "resources")))
	router.PathPrefix("/generated").HandlerFunc(protectedFiles(path.Join(cwd, "resources", "webshells")))
	router.PathPrefix("/looted").HandlerFunc(protectedFiles(path.Join(cwd, "resources")))
	router.PathPrefix("/archives").HandlerFunc(protectedAdminFiles(path.Join(cwd)))
	router.HandleFunc("/log.in", login)
	router.HandleFunc("/log.out", logout)
	router.HandleFunc("/set.up", firstSetup)
	router.HandleFunc("/change.pass", changePass)
	router.HandleFunc("/token", mfaSubmit)

	/*
		Listener REST API routes
	*/
	router.HandleFunc("/listener/list", listenerList)
	router.HandleFunc("/listener/add", listenerAdd)
	router.HandleFunc("/listener/{key}/kill", listenerKill)
	router.HandleFunc("/listener/{key}/createagent", listenerCreateAgent)
	router.HandleFunc("/listener/{key}/privatekey", listenerGetListenerPrivateKey)
	router.HandleFunc("/listener/{key}/compiled", listenerGetCompiled)
	router.HandleFunc("/listener/{key}/edit", listenerEdit)

	//Serve the main application
	router.PathPrefix("/").HandlerFunc(http.HandlerFunc(index(cwd)))

	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
	}

	srv := &http.Server{
		Handler:      router,
		Addr:         ":" + c.WebserverPort,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	certPath := path.Join(cwd, "resources", serverConfig.Cert)
	keyPath := path.Join(cwd, "resources", serverConfig.Key)

	srv.ListenAndServeTLS(certPath, keyPath)
}

func index(cwd string) func(w http.ResponseWriter, r *http.Request) {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if serverConfig.Setup && r.RequestURI != "/setup" {
			http.Redirect(w, r, "/setup", 302)
		}
		http.ServeFile(w, r, path.Join(cwd, "resources", "frontend", "static", "index.html"))
	}
	return http.HandlerFunc(fn)
}

//Directory access to files if the user is authenticated
func protectedFiles(dir string) http.HandlerFunc {
	fs := http.FileServer(http.Dir(dir))
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "Operator")
		val := session.Values["User"]
		uID := User{}
		uID, ok := val.(User)
		if !ok || !uID.Authenticated {
			http.Redirect(w, r, "/login", http.StatusFound)
		} else {
			fs.ServeHTTP(w, r)
		}
	}
}

//Directory access to files if the user is authenticated
func protectedAdminFiles(dir string) http.HandlerFunc {
	fs := http.FileServer(http.Dir(dir))
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "Operator")
		val := session.Values["User"]
		uID := User{}
		uID, ok := val.(User)
		if !ok || !uID.Authenticated {
			http.Redirect(w, r, "/login", http.StatusFound)
		} else {
			if uID.Admin {
				fs.ServeHTTP(w, r)
			} else {
				http.Redirect(w, r, "/", http.StatusFound)
			}
		}
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "Operator")

	val := session.Values["User"]
	uID := User{}
	uID, ok := val.(User)
	if ok && uID.Authenticated {
		http.Redirect(w, r, "/", http.StatusFound)
	}

	decoder := json.NewDecoder(r.Body)

	var data loginForm
	err := decoder.Decode(&data)
	if err != nil && err.Error() != "EOF" {
		logging.ErrorLogger.Println(err.Error())
	}
	username := data.Username
	password := data.Password

	//Now that the data is there just pass the username and the password to a function in order to verify if they are correct or not.
	auth := false
	var userid string
	var admin bool
	var firstTime bool
	var mfaRquired bool
	var mfaSetup bool
	if username != "" && password != "" {
		auth, userid, admin, firstTime, mfaRquired, mfaSetup = sqldb.Login(username, password)
	}

	if !auth {
		//return that it failed then send back to login
		http.Error(w, "Maybe get your password right?", 401)
		return
	}

	user := &User{
		UserID:         userid,
		Username:       username,
		Authenticated:  auth,
		Admin:          admin,
		ChangePassword: firstTime,
		MFASetup:       mfaRquired,
		MFA:            mfaSetup,
	}

	//Assign the user cookie "Operator" for users overall auth session
	session.Values["User"] = user
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func changePass(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "Operator")
	val := session.Values["User"]
	logging.Logger.Println(val)
	uID := User{}
	uID, ok := val.(User)
	//If not authed kill
	if !ok || !uID.Authenticated {
		http.Redirect(w, r, "/login", 302)
	} else {
		decoder := json.NewDecoder(r.Body)

		var data changePassword
		err := decoder.Decode(&data)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}
		//Get data from POST request
		oldpass := data.OldPass
		newpass := data.NewPass
		if oldpass != newpass {
			//Send userid, newpass, and oldpass to SQL query to ensure old pass is correct and if so change password
			success, message := sqldb.ChangeUserPassword(uID.UserID, newpass, oldpass)
			if !success {
				//Present Error Message
				http.Error(w, message, 401)
			}
		} else {
			http.Error(w, "Can't use your old password!", 401)
		}
	}
}

func logout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "Operator")

	session.Values["User"] = User{}
	session.Options.MaxAge = -1

	err := session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	//Needs to be changed to redirect to the login page
	http.Redirect(w, r, "/", http.StatusFound)
}

//Adds the first admin user and then send to the login page.
func firstSetup(w http.ResponseWriter, r *http.Request) {
	if !serverConfig.Setup {
		http.Error(w, "Maybe go away?", 406)
		return
	}

	decoder := json.NewDecoder(r.Body)

	var data setupForm
	err := decoder.Decode(&data)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	//Username and Password of first time admin
	username := data.Username
	password := data.Password
	//Bool value of MFA
	mfa := data.MFA
	//Pass length value
	passlength := data.PassLength

	if username != "" && password != "" {
		//Setting up the first admin user from data passed in the POST request
		success := sqldb.FirstUser(username, password)
		if !success {
			logging.Logger.Println("Adding first time admin failed!")
			serverConfig.Setup = true

		} else {
			//If adding the user was successful we take the MFA and passlength data and set it in App Settings table in DB
			sqldb.InitAppSettings(mfa, passlength)
			serverConfig.Setup = false
		}
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

//Generate MFA secret and QR code for user
func mfaGenerate(userID string, ws *websocket.Conn) {
	//If secret exists for user don't generate again else generate
	exists := sqldb.CheckMFA(userID)
	if exists {
		logging.Logger.Println("MFA Already Generated!")
	} else {
		secret, qrCode, err := mfa.GenerateNewSecretAndImage(userID, "DeimosC2")
		if err != nil {
			logging.ErrorLogger.Println("MFA Error: ", err.Error())
		}

		//Send QR to FE
		msg := websockets.SendMessage{
			Type:         "QRCode",
			FunctionName: "",
			Data:         qrCode,
			Success:      true,
		}
		websockets.AlertSingleUser(msg, ws)

		//Save secret in DB
		success := sqldb.SetupMFA(userID, secret)
		if !success {
			msg := websockets.SendMessage{
				Type:         "Failed to save to DB",
				FunctionName: "",
				Data:         qrCode,
				Success:      true,
			}
			websockets.AlertSingleUser(msg, ws)
		}
	}
}

//Grab MFA token from POST request
func mfaSubmit(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "Operator")
	val := session.Values["User"]
	logging.Logger.Println(val)
	uID := User{}
	uID, ok := val.(User)
	//If not authed kill
	if !ok || !uID.Authenticated {
		http.Redirect(w, r, "/login", 302)
	} else {
		//Get secret from DB
		secret := sqldb.GetMFASecret(uID.UserID)

		decoder := json.NewDecoder(r.Body)

		var data mfaForm
		err := decoder.Decode(&data)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}

		//Username and Password of first time admin
		token := data.Token

		//Validate token and secret match
		success := mfa.IsTokenValid(secret, token)

		if success {
			uID.MFASuccess = true
			uID.MFA = true
			session.Values["User"] = uID
			err = session.Save(r, w)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Write([]byte("Successful MFA\n"))
		} else {
			http.Error(w, "Token Failed", 401)
		}
	}
}
