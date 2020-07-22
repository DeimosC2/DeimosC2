import Vue from "vue";
import Vuex from "vuex";

Vue.use(Vuex);

export default {
  namespaced: false,
  state: {
    SocketConnected: false,
    ReconnectError: false,
    initialized: false,
    connectionStarted: false
  },
  getters: {
    SOCKET_CONNECTED: state => state.SocketConnected
  },
  mutations: {
    // VueNativeWebsockets standard mutations scaffold
    SOCKET_ONOPEN(state, event) {
      Vue.prototype.$socket = event.currentTarget;
      state.SocketConnected = true;
      Vue.prototype.$c2.Listener.GetListeners();
      Vue.prototype.$c2.Agent.GetAgents();
      Vue.prototype.$c2.WebShell.ListShells();
    },
    SOCKET_ONCLOSE(state) {
      state.SocketConnected = false;
      console.log("Web socket closed.");
    },
    // eslint-disable-next-line
    SOCKET_ONERROR(state, event) {
      Vue.prototype.$notify({ type: "danger", message: "Socket Error" });
    },
    // default handler called for all methods
    // eslint-disable-next-line
    SOCKET_ONMESSAGE(state, message) {
      if (typeof message === "object") {
        Vue.prototype.$c2.MessageRouter(message);
      } else {
        console.warn(`Web Socket Received: ${message}`);
      }
    },
    // mutations for reconnect methods
    SOCKET_RECONNECT(state) {
      state.initialized = false;
      state.connectionStarted = false;
    },
    SOCKET_RECONNECT_ERROR(state) {
      state.SocketConnected = false;
      state.ReconnectError = true;
      state.initialized = false;
      state.connectionStarted = false;
    },
    connectionStarted(state) {
      state.connectionStarted = true;
    }
  },
  actions: {
    SOCKET_CONNECT(context) {
      if (!context.state.connectionStarted) {
        context.commit("connectionStarted");
        Vue.prototype.$connect();
      }
    }
  }
};
