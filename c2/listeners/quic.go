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

	"github.com/AdvancedThreatAnalytics/DeimosC2/c2/lib/certs"
	"github.com/AdvancedThreatAnalytics/DeimosC2/c2/lib/validation"
	"github.com/AdvancedThreatAnalytics/DeimosC2/lib/logging"
	"github.com/gorilla/mux"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
)

//StartQUICServer will start up a Quic Listener
func StartQUICServer(newListener ListOptions, pr []byte, pu []byte) (*http3.Server, bool) {

	logging.Logger.Println("Starting QUIC Listener")

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
	qcfg := &quic.Config{
		KeepAlive: false,
	}

	srv := &http.Server{
		Handler:      router,
		Addr:         ":" + newListener.Port,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	server := http3.Server{
		Server:     srv,
		QuicConfig: qcfg,
	}

	logging.Logger.Println("Serving the Quic Listener")
	var success = false
	ln, err := net.Listen("tcp", ":"+newListener.Port)
	if err != nil {
		success = false

	} else {
		success = true
	}
	ln.Close()

	go server.ListenAndServeTLS(certPath, keyPath)

	return &server, success
}
