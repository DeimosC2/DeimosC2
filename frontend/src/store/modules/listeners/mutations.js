import Vue from "vue";

function insertIfNotExist(state, _var) {
  const index = state.listeners.findIndex(x => x.Key === _var.Key);
  if (index !== -1) {
    Vue.set(state.listeners, index, _var);
  } else {
    state.listeners.push(_var);
  }
}

// Make synchronous changes to state
export const initialize = (state, _var) => {
  state.initialized = _var;
};

export const createListener = (state, _var) => {
  insertIfNotExist(state, _var);
};

export const editListener = (state, _var) => {
  insertIfNotExist(state, _var);
};

export const killListener = (state, _var) => {
  const index = state.listeners.findIndex(x => x.Key === _var.Name);
  if (index >= 0) {
    state.listeners.splice(index);
  }
};

export const updateSettings = (state, _var) => {
  state.settings = _var;
};

export const flushState = state => {
  state.listeners = [];
};

export const getCompiled = (state, _var) => {
  state.agents = _var;
};

export default {
  initialize,
  createListener,
  editListener,
  killListener,
  updateSettings,
  flushState,
  getCompiled
};
