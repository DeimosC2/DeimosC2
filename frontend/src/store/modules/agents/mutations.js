import Vue from "vue";

// Make synchronous changes to state
export const initialize = (state, _var) => {
  state.initialized = _var;
};

export const populateAgents = (state, _var) => {
  state.agents = _var;
  state.count = state.agents.length;
};

export const flushState = state => {
  state.agents = [];
  state.count = state.agents.length;
};

export const setFilesToUpload = (state, _var) => {
  state.filesToUpload = _var;
};

export const clearFiles = state => {
  state.filesToUpload = [];
};

export const heartBeat = (state, _var) => {
  Vue.set(_var.agent, "LastCheckin", Vue.options.filters.datetime(_var.Time));
};

export const updateSettings = (state, _var) => {
  state.modulesSettings = _var;
};

export const addComments = (state, _var) => {
  Vue.set(state.comments, _var.AgentKey, _var.Data);
};

export default {
  initialize,
  populateAgents,
  flushState,
  setFilesToUpload,
  clearFiles,
  heartBeat,
  updateSettings,
  addComments
};
