// Makes Mutations run asychronously
// export const actionFunction = {
//   return stuff;
// }

import Vue from "vue";

export const generateWebShell = (context, _var) => {
  Vue.prototype.$c2.WebShell.GenerateShell(_var);
};

export const initWebShell = (context, _var) => {
  Vue.prototype.$c2.WebShell.InitWebShell(_var);
};

export const deleteWebShell = (context, _var) => {
  Vue.prototype.$c2.WebShell.DeleteWebShell({ UUID: _var.UUID, Options: {} });
};

export const fetchGeneratedWebShells = () => {
  // TODO: fetch and store. Convert to the object if it returned in other format
  // Vue.prototype.$c2.WebShell.FetchGeneratedWebShells();
};

export const fileBrowser = (context, _var) => {
  Vue.prototype.$c2.WebShell.FileBrowser({
    UUID: _var.credentials,
    Options: [_var.startPoint, ""]
  });
};

export const downloadFile = (context, _var) => {
  Vue.prototype.$c2.WebShell.FileBrowser({
    UUID: _var.credentials,
    Options: [_var.path, "download"]
  });
};

export const readFile = (context, _var) => {
  context.commit("editingFilePath", _var.path);
  Vue.prototype.$c2.WebShell.FileEditor({
    UUID: _var.credentials,
    Options: [_var.path, "read", ""]
  });
};

export const writeFile = (context, _var) => {
  Vue.prototype.$c2.WebShell.FileEditor({
    UUID: _var.credentials,
    Options: [_var.path, "write", _var.content]
  });
};

export const makeDir = (context, _var) => {
  Vue.prototype.$c2.WebShell.FileBrowser({
    UUID: _var.credentials,
    Options: [_var.path, "mkdir"]
  });
};

export const removeFile = (context, _var) => {
  Vue.prototype.$c2.WebShell.FileBrowser({
    UUID: _var.credentials,
    Options: [_var.path, "remove"]
  });
};

export const fileUpload = (context, _var) => {
  _var.files.forEach(file => {
    Vue.prototype.$c2.WebShell.FileUpload({
      UUID: _var.credentials,
      Options: [file.name, _var.path, file.b64]
    });
  });
};

export const listShells = () => {
  Vue.prototype.$c2.WebShell.ListShells();
};

export const sendJob = (context, _var) => {
  return Vue.prototype.$c2.WebShell.sendJob(_var);
};

export const waitForInitialization = context => {
  Vue.prototype.$logging("Store::webshells:actions:waitForInitialzation", context.rootState.debug);
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

export default {
  generateWebShell,
  initWebShell,
  deleteWebShell,
  fetchGeneratedWebShells,
  waitForInitialization,
  fileBrowser,
  downloadFile,
  readFile,
  writeFile,
  sendJob,
  makeDir,
  removeFile,
  fileUpload,
  listShells
};
