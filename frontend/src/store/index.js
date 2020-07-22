import Vue from "vue";
import Vuex from "vuex";

import agents from "./modules/agents/agents";
import listeners from "./modules/listeners/listeners";
import webShells from "./modules/webShells/webshells";
import metrics from "./modules/metrics/metrics";
import loot from "./modules/loot/loot";
import socket from "./socket";
import term from "./term";
import admin from "./modules/admin/admin";

Vue.use(Vuex);

const store = new Vuex.Store({
  state: {
    env: process.env.VUE_APP_ENV,
    experimental: process.env.VUE_APP_EXP === "true",
    auth: {
      userName: null,
      userID: null,
      loggedIn: false,
      processingLogin: false,
      isAdmin: false,
      mustChangePassword: false,
      mustEnterMFA: false,
      qrCode: null
    },
    debug: process.env.VUE_APP_EXP === "true",
    server: {
      host: window.location.host,
      hostname: window.location.hostname,
      port: window.location.port
    },
    modal: {
      show: false,
      type: null,
      data: {}
    },
    langs: ["en", "ru", "fr", "cn"],
    dust: {
      pageReady: false,
      dustReady: false,
      start: false
    }
  },
  getters: {
    isAuthenticated: state => state.auth.loggedIn
  },
  mutations: {
    updateSocketServer(state, newServer) {
      state.server.host = newServer;
    },
    login(state, _var) {
      state.auth.loggedIn = _var;
    },
    processingLogin(state, _var) {
      state.auth.processingLogin = _var;
    },
    toggleDebug(state) {
      state.debug = !state.debug;
    },
    toggleExperimental(state) {
      state.experimental = !state.experimental;
    },
    setEnv(state, _var) {
      state.env = _var;
    },
    updateModalStatus(state, _var) {
      state.modal.show = _var.show;
      state.modal.type = _var.type;
      state.modal.data = _var.data;
    },
    forceToChangePassword(state, _var) {
      state.auth.mustChangePassword = _var;
    },
    forceToEnterMFA(state, _var) {
      state.auth.mustEnterMFA = _var;
    },
    setQRCode(state, _var) {
      state.auth.qrCode = _var;
    },
    markPageAsReadyForDust(state, _var) {
      state.dust.pageReady = _var;
    },
    startDust(state, _var) {
      state.dust.start = _var;
    },
    readyToDust(state, _var) {
      state.dust.dustReady = _var;
      console.log("dust state", state.dust);
    },
    setUser(state, _var) {
      state.auth.userName = _var.UserName;
      state.auth.userID = _var.UserID;
      state.auth.isAdmin = _var.Admin === "true";
    }
  },
  actions: {
    checkAuth(context, user = {}) {
      let prom = null;
      if (Object.entries(user).length === 0 && user.constructor === Object) {
        context.commit("processingLogin", true);
        // calling without user tests cookie validity with get request
        Vue.prototype.$logging("Store::actions:checkAuth:verify cookie");
        prom = Vue.prototype.$axios
          .get("/log.in")
          .then(response => {
            Vue.prototype.$logging(`Store::actions:checkAuth:response=${response}`);
            if (response.status === 200) {
              context.dispatch("markUserAsLoggedIn");
            }
          })
          .catch(error => {
            Vue.prototype.$logging(`Store::actions:checkAuth:error=${error}`);
            if (error.response.status === 401) {
              context.commit("login", false);
              context.commit("processingLogin", false);
            }
          });
      } else {
        Vue.prototype.$logging(
          `Store::actions:checkAuth:submiting credentials for user '${user.username}'`
        );
        context.commit("processingLogin", true);
        prom = Vue.prototype.$axios
          .post("/log.in", user)
          .then(response => {
            Vue.prototype.$logging({
              type: "success",
              message: `Store::actions:checkAuth:response.status=${response.status}`
            });
            if (response.status === 200) {
              Vue.prototype.$notify({ type: "success", message: "Login Success" });
              context.dispatch("markUserAsLoggedIn");
            }
          })
          .catch(error => {
            Vue.prototype.$logging(`Store::actions:checkAuth:error=${error}`);
            if (error.response.status === 401) {
              Vue.prototype.$notify({ type: "danger", message: "Login Failed" });
              context.commit("login", false);
              context.commit("processingLogin", false);
            }
          });
      }
      return prom;
    },
    clearSaving(context) {
      context.commit("listeners/saving", false);
      context.commit("webShells/saving", false);
    },
    openModal(context, _var) {
      context.commit("updateModalStatus", { show: true, type: _var.type, data: _var.data });
    },
    closeModal(context) {
      context.commit("updateModalStatus", { show: false, type: null, data: {} });
    },
    markUserAsLoggedIn(context) {
      context.commit("login", true);
      context.commit("processingLogin", false);
    },
    setMFARequired(context) {
      context.commit("forceToEnterMFA", true);
    },
    sendToken(context, _var) {
      Vue.prototype.$axios
        .post("/token", { token: _var }, { withCredentials: true })
        .then(() => {
          window.location.href = "/";
        })
        .catch(err => {
          Vue.prototype.$notify({ type: "danger", message: err.response.data });
        });
    }
  },
  modules: {
    agents,
    listeners,
    webShells,
    metrics,
    loot,
    socket,
    term,
    admin
  }
});

store.subscribe((mutation, state) => {
  if (mutation.type === "webShells/jobOutput" && mutation.payload) {
    const output = `[[gb;green;][+>] Shell Output:\n${mutation.payload.Results}`;
    store.commit("term/setOutput", output);
  } else if (mutation.payload && mutation.payload.AgentKey === state.term.agentKey) {
    if (mutation.type === `${state.term.currentModule}/jobOutput`) {
      let output = "";
      let path = "";
      let downloadUrl = "";
      switch (mutation.payload.JobName) {
        case "shell":
          output = `[[gb;green;][+>] Shell Output:\n${mutation.payload.Results}`;
          Vue.prototype.$logging(
            `Term::mounted():subcribe:switch>shell:mutation.payload=${JSON.stringify(
              mutation.payload
            )}`,
            state.debug
          );
          Vue.prototype.$logging(`WATCHER>output=${output}`, state.debug);
          store.commit("term/setOutput", output);
          break;
        case "download":
          Vue.prototype.$logging(
            `Term::mounted():subcribe:switch>download:mutation.payload=${JSON.stringify(
              mutation.payload
            )}`,
            state.debug
          );
          path = `${mutation.payload.Results}`;
          downloadUrl = `https://${store.state.server.host}/${path}`;
          output = `[[gb;green;][+>] Shell Output:\n${downloadUrl}`;
          Vue.prototype.$logging(`WATCHER>path=${path}`, state.debug);
          Vue.prototype.$logging(`WATCHER>output=${output}`, state.debug);
          store.commit("term/setOutput", output);
          break;
        default:
          break;
      }
    } else if (mutation.type === `${state.term.currentModule}/moduleOutput`) {
      Vue.prototype.$logging(
        `Term::mounted():subcribe:moduleOutput:mutation.payload=${JSON.stringify(
          mutation.payload
        )}`,
        state.debug
      );
      const path = `${mutation.payload.Output}`;
      Vue.prototype.$logging(`WATCHER>path=${path}`, state.debug, "warn");
      if (mutation.payload.OutputType === "Link") {
        const downloadUrl = `https://${store.state.server.host}/looted/${mutation.payload.AgentKey}/files/${path}`;
        const output = `[[gb;green;][+>] Module ${mutation.payload.ModuleName} Output:\n${downloadUrl}`;
        store.commit("term/setOutput", output);
      } else {
        store.commit("term/setOutput", path);
      }
    }
  }
});

export default store;
