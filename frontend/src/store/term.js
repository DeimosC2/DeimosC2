export default {
  namespaced: true,
  state: {
    agentKey: null,
    currentModule: null,
    output: null
  },
  mutations: {
    setAgentKey(state, agentKey) {
      state.agentKey = agentKey;
    },
    setCurrentModule(state, moduleName) {
      state.currentModule = moduleName;
    },
    setOutput(state, output) {
      state.output = output;
    }
  }
};
