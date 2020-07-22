// Makes Mutations run asychronously
// export const actionFunction = {
//   return stuff;
// }

import Vue from "vue";
import axios from "axios";

export const listAgents = () => {
  Vue.prototype.$c2.Agent.GetAgents();
};

export const registerAgent = (context, _var) => {
  Vue.prototype.$c2.Agent.register(_var);
};

export const deregisterAgent = (context, _var) => {
  Vue.prototype.$c2.Agent.deregister(_var);
};

export const sendJob = (context, _var) => {
  return Vue.prototype.$c2.Agent.sendJob(_var.name, _var.action, _var.options);
};

export const sendModule = (context, _var) => {
  return Vue.prototype.$c2.Agent.sendModule(_var);
};

export const waitForInitialization = context => {
  Vue.prototype.$logging("Store::agents:actions:waitForInitialzation", context.rootState.debug);
  const start = Date.now();
  const timeout = 1000;
  console.log("context = ", context);

  function waitForInit(resolve, reject) {
    if (context.state.initialized) resolve(context.state.initialized);
    else if (timeout && Date.now() - start >= timeout) reject(new Error("timeout"));
    else setTimeout(waitForInit.bind(this, resolve, reject), 30);
  }

  return new Promise(waitForInit);
};

export const fileBrowser = (context, _var) => {
  // Vue.prototype.$c2.Loot.ListLootFiles(_var.credentials);
  Vue.prototype.$c2.Agent.sendJob(_var.credentials, "fileBrowser", [_var.startPoint]);
};

export const downloadFile = (context, _var) => {
  Vue.prototype.$c2.Agent.sendJob(_var.credentials, "download", [_var.path]);
};

export const fileUpload = (context, _var) => {
  _var.files.forEach(file => {
    Vue.prototype.$c2.Agent.sendJob(_var.credentials, "upload", [_var.path, file.name, file.b64]);
  });
};

export const getModulesSettings = context => {
  axios.get(`/config/modules.json`).then(response => {
    context.commit("updateSettings", response.data);
  });
};

export const heartBeat = (context, _var) => {
  const agent = context.getters.getAgentByKey(_var.AgentKey);
  if (agent) {
    context.commit("heartBeat", { agent, Time: _var.Time, AgentKey: _var.AgentKey });
  }
};

export const removeAgent = (context, _var) => {
  return Vue.prototype.$c2.Agent.removeAgent(_var);
};

export const fetchComments = (context, _var) => {
  return Vue.prototype.$c2.Agent.fetchComments(_var);
};

export const sendComment = (context, _var) => {
  return Vue.prototype.$c2.Agent.sendComment(_var);
};

export const setName = (context, _var) => {
  Vue.prototype.$c2.Agent.setName(_var);
};

export default {
  listAgents,
  registerAgent,
  deregisterAgent,
  sendJob,
  sendModule,
  waitForInitialization,
  fileBrowser,
  downloadFile,
  fileUpload,
  getModulesSettings,
  heartBeat,
  removeAgent,
  fetchComments,
  sendComment,
  setName
};
