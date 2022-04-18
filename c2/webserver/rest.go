package webserver

import (
	"encoding/json"
	"net/http"

	"github.com/DeimosC2/DeimosC2/c2/lib"
	"github.com/DeimosC2/DeimosC2/c2/lib/sqldb"
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

func listenerList(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
	}

	json.NewEncoder(w).Encode(lib.ListListeners())

}

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
}

func listenerEdit(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

/*

	Below is the list of Agent Functions that are exposed to the REST API

*/
