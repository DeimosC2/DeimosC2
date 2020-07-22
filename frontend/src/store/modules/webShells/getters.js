// 'state' references the module state, not the global state
// getters are for computed properties, for data state can be used directly

export const getWebShellByUUID = state => UUID =>
  state.webShells.find(shell => shell.UUID === UUID);

export default {
  getWebShellByUUID
};
