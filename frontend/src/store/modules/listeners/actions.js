// Makes Mutations run asychronously
// export const actionFunction = {
//   return stuff;
// }

import Vue from "vue";
import axios from "axios";

export const createListener = (context, _var) => {
  Vue.prototype.$c2.Listener.AddListener(_var);
};

export const editListener = (context, _var) => {
  Vue.prototype.$c2.Listener.EditListener(_var);
};

export const waitForInitialization = context => {
  Vue.prototype.$logging("Store::listeners:actions:waitForInitialzation", context.rootState.debug);
  const start = Date.now();
  const timeout = 5000;
  // const { initialized } = context.state;
  console.log("context = ", context);

  function waitForInit(resolve, reject) {
    if (context.state.initialized) resolve(context.state.initialized);
    else if (timeout && Date.now() - start >= timeout) reject(new Error("timeout"));
    else setTimeout(waitForInit.bind(this, resolve, reject), 30);
  }

  return new Promise(waitForInit);
};

export const getListenersSettings = context => {
  axios.get(`/config/listeners.json`).then(response => {
    context.commit("updateSettings", response.data);
  });
};

export const killListener = (context, _var) => {
  Vue.prototype.$c2.Listener.KillListener(_var);
};

export const getListenerPrivateKey = (context, _var) => {
  Vue.prototype.$c2.Listener.GetListenerPrivateKey(_var);
};

export const createAgent = (context, _var) => {
  Vue.prototype.$c2.Listener.CreateAgent(_var);
};

export const getCompiledAgents = (context, _var) => {
  Vue.prototype.$c2.Listener.GetCompiledAgents({ Key: _var });
};

export default {
  createListener,
  editListener,
  waitForInitialization,
  getListenersSettings,
  killListener,
  getListenerPrivateKey,
  createAgent,
  getCompiledAgents
};
