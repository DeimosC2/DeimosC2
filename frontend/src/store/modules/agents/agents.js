import state from "./state";
import actions from "./actions";
import getters from "./getters";
import mutations from "./mutations";

import Term from "../../base/term";
import FileManager from "../../base/fileManager";

const term = new Term();
const fileManager = new FileManager();

export default {
  namespaced: true,
  state: {
    ...term.state,
    ...fileManager.state,
    ...state
  },
  actions,
  getters: {
    ...fileManager.getters,
    ...getters
  },
  mutations: {
    ...term.mutations,
    ...fileManager.mutations,
    ...mutations
  }
};
