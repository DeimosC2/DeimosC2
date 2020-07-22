import Vue from "vue";
import store from "../store/index";

let entryUrl = null;

export const guard = async (to, from, next) => {
  // check if Authenticated, if so send the user to the entry route
  // console.log(`Router::guard:entryUrl = ${entryUrl}`);

  // Allow route access if authenticated
  if (store.getters.isAuthenticated) {
    // console.log('Router::guard:User Already Authenticated');
    // On first auth, send user to their intended route
    if (entryUrl) {
      // console.log(`Router::guard:Directing User to entryUrl: ${entryUrl}`);
      const url = entryUrl;
      entryUrl = null;
      next(url); // goto stored url
    } else {
      // console.log('Router::guard:Permitting Route Access');
      next(); // all is fine
    }
  } else {
    // console.log('Router::guard:User Not Authenticated');
    // we use await as this async request has to finish
    // before we can be sure
    await store.dispatch("checkAuth"); // checking cookie validity
    // console.log('Router::guard:Check Auth Complete');
  }

  if (store.getters.isAuthenticated) {
    if (store.state.auth.mustChangePassword) {
      next("/change-password");
    }

    // console.log('Router::guard:User Authenticated');
    // console.log(`entryUrl = ${entryUrl}`);
    if (!store.getters.SOCKET_CONNECTED) store.dispatch("SOCKET_CONNECT");
    next();
  } else {
    // Sending user to Login Page
    entryUrl = to.path; // store entry url before redirect
    // console.log(`Router::guard:Redirecting to Login:entryUrl = ${entryUrl}`);
    next("/login");
  }
};

export const isAuthorized = async (to, from, next) => {
  if (!store.getters.isAuthenticated) {
    await store.dispatch("checkAuth");
    // eslint-disable-next-line
    store.getters.isAuthenticated ? next("/") : next();
  } else {
    next("/");
  }
};

export const ifAgentExists = (to, from, next) => {
  const { agentUUID } = to.params;
  store
    .dispatch("agents/waitForInitialization")
    .then(() => {
      if (store.getters["agents/getAgentByKey"](agentUUID)) {
        Vue.prototype.$logging(
          `Router::guards:beforeRouteEnter:routing to agent ${agentUUID}`,
          store.state.debug
        );
        next();
      } else {
        Vue.prototype.$logging(
          "Router::guards:beforeRouteEnter:rejecting back to agents",
          store.state.debug
        );
        next("/agents");
      }
    })
    .catch(error => {
      Vue.prototype.$logging(["Router::guards:beforeRouteEnter:error=", error], store.state.debug);
      next("/agents");
    });
};

export const ifWebshellExists = (to, from, next) => {
  const { shellUUID } = to.params;
  if (store.getters["webShells/getWebShellByUUID"](shellUUID)) {
    Vue.prototype.$logging(
      `Webshells::beforeRouteEnter:routing to webshell ${shellUUID}`,
      store.state.debug
    );
    next();
  } else {
    next("/webshells");
  }
};

export const ifListenerExists = (to, from, next) => {
  const { listenerName } = to.params;
  store.dispatch("listeners/waitForInitialization").then(
    () => {
      if (store.getters["listeners/getListenerByKey"](listenerName)) {
        Vue.prototype.$logging(
          `ListenerInterface::beforeRouteEnter:routing to Listener ${listenerName}`,
          store.state.debug
        );
        next();
      } else {
        Vue.prototype.$logging(
          "ListenerInterface::beforeRouteEnter:rejecting back to listeners",
          store.state.debug
        );
        next("listeners");
      }
    },
    () => {
      Vue.prototype.$logging(
        "ListenerInterface::beforeRouteEnter:Timing out back to listeners",
        store.state.debug
      );
      next("listeners");
    }
  );
};

export const isAdmin = (to, from, next) => {
  if (store.state.auth.isAdmin) {
    next();
  } else next("/");
};

export default {
  guard,
  isAuthorized,
  ifAgentExists,
  ifWebshellExists,
  ifListenerExists,
  isAdmin
};
