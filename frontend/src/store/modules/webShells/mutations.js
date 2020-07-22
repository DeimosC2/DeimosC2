export const initialize = (state, _var) => {
  state.initialized = _var;
};

export const addGeneratedFile = (state, _var) => {
  state.generatedShells.push(_var);
};

export const populateWebShells = (state, _var) => {
  state.webShells = _var;
};

export const addShell = (state, _var) => {
  if (Array.isArray(_var)) {
    _var.forEach(item => {
      state.webShells.push(item);
    });
  } else {
    state.webShells.push(_var);
  }
};

export default {
  initialize,
  addGeneratedFile,
  addShell,
  populateWebShells
};
