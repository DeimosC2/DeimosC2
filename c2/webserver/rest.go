package webserver

import (
	"encoding/json"
	"net/http"

	"github.com/DeimosC2/DeimosC2/c2/lib"
	"github.com/DeimosC2/DeimosC2/c2/listeners"
)

/*
	This file holds all the REST API functions



*/

/*

	Below is the list of Listener Functions that are exposed to the REST API

*/

func listenerList(w http.ResponseWriter, r *http.Request) {

	lib.AllListeners.mutex.Lock()
	defer lib.AllListeners.mutex.Unlock()
	list := []listeners.ListOptions{}
	for _, v := range lib.AllListeners.list {
		l := listeners.ListOptions{
			LType:        v.LType,
			Name:         v.Name,
			Host:         v.Host,
			Port:         v.Port,
			Key:          v.Key,
			Advanced:     v.Advanced,
			AgentOptions: v.AgentOptions,
		}
		list = append(list, l)
	}
	json.NewEncoder(w).Encode(list)
	return
}

func listenerKill(w http.ResponseWriter, r *http.Request) {

}

func listenerCreateAgent(w http.ResponseWriter, r *http.Request) {

}

func listenerGetListenerPrivateKey(w http.ResponseWriter, r *http.Request) {

}

func listenerGetCompiled(w http.ResponseWriter, r *http.Request) {

}

func listenerAdd(w http.ResponseWriter, r *http.Request) {

}

func listenerEdit(w http.ResponseWriter, r *http.Request) {

}

/*

	Below is the list of Agent Functions that are exposed to the REST API

*/
