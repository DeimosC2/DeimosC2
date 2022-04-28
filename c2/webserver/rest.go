package webserver

import (
	"encoding/json"
	"net/http"

	"github.com/DeimosC2/DeimosC2/c2/lib"
	"github.com/DeimosC2/DeimosC2/c2/lib/sqldb"
	"github.com/DeimosC2/DeimosC2/c2/listeners"
	"github.com/DeimosC2/DeimosC2/lib/logging"
	"github.com/gorilla/mux"
)

/*
	This file holds all the REST API functions



*/

//isAuthed returns if the user is authentiated or not
func isAuthed(r *http.Request) bool {
	session, _ := store.Get(r, "Operator")
	val := session.Values["User"]
	uID := User{}
	uID, ok := val.(User)
	if !ok || !uID.Authenticated {
		return false
	} else {
		return true
	}
}

/*

	Below is the list of Listener Functions that are exposed to the REST API

*/

//Lists all the active listeners
func listenerList(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
	}

	json.NewEncoder(w).Encode(lib.ListListeners())

}

//Kills the given listener
func listenerKill(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
	}

	vars := mux.Vars(r)
	key := vars["key"]

	lib.StopListener(key)

	resp := struct {
		Name string `json:"name"`
	}{
		Name: key,
	}
	json.NewEncoder(w).Encode(resp)

}

func listenerCreateAgent(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

//returns the private key f
func listenerGetListenerPrivateKey(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
	}
	vars := mux.Vars(r)
	key := vars["key"]

	privKey := sqldb.GetListenerPrivateKey(key)

	resp := struct {
		PrivateKey string `json:"privatekey"`
	}{
		PrivateKey: privKey,
	}
	json.NewEncoder(w).Encode(resp)
}

//listenerGetCompiled returns the compiled binaries for the listener requested
func listenerGetCompiled(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
	}
	vars := mux.Vars(r)
	key := vars["key"]

	_, files := lib.GetCompiled(key)

	json.NewEncoder(w).Encode(files)

}

func listenerAdd(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
	}
	session, _ := store.Get(r, "Operator")
	val := session.Values["User"]
	uID := User{}
	uID, ok := val.(User)
	if !ok {
		return
	}

	decoder := json.NewDecoder(r.Body)
	listener := listeners.ListOptions{}
	err := decoder.Decode(&listener)
	if err != nil {
		logging.Logger.Println(err)
		return
	}

	success, newL := lib.StartNewListener(listener, uID.UserID, true, listener.Gooses, listener.Obfuscation, uID.Username)

	if !success {
		//we need to handle these
		logging.Logger.Println("failure to start listener")
	}

	//TODO: this makes no fucking sense, why isnt the above call a method?
	l := listeners.ListOptions{
		LType:        newL.LType,
		Name:         newL.Name,
		Host:         newL.Host,
		Port:         newL.Port,
		Key:          newL.Key,
		Advanced:     newL.Advanced,
		AgentOptions: newL.AgentOptions,
	}
	newMsg, _ := json.Marshal(l)

	json.NewEncoder(w).Encode(newMsg)

}

func listenerEdit(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
	}

	session, _ := store.Get(r, "Operator")
	val := session.Values["User"]
	uID := User{}
	uID, ok := val.(User)
	if !ok {
		return
	}

	decoder := json.NewDecoder(r.Body)
	listener := listeners.ListOptions{}
	err := decoder.Decode(&listener)
	if err != nil {
		logging.Logger.Println(err)
		return
	}

	lib.StopListener(listener.Key)

	success, newL := lib.StartNewListener(listener, uID.UserID, true, listener.Gooses, listener.Obfuscation, uID.Username)

	if !success {
		//we need to handle these
		logging.Logger.Println("failure to start listener")
	}

	//TODO: this makes no fucking sense, why isnt the above call a method?
	l := listeners.ListOptions{
		LType:        newL.LType,
		Name:         newL.Name,
		Host:         newL.Host,
		Port:         newL.Port,
		Key:          newL.Key,
		Advanced:     newL.Advanced,
		AgentOptions: newL.AgentOptions,
	}
	newMsg, _ := json.Marshal(l)

	json.NewEncoder(w).Encode(newMsg)

}

/*

	Below is the list of Agent Functions that are exposed to the REST API

*/
