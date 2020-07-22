import Processing from "../../base/processing";
import FileManager from "../../base/fileManager";
import Term from "../../base/term";

import state from "./state";
import actions from "./actions";
import getters from "./getters";
import mutations from "./mutations";

const processing = new Processing();
const fileManager = new FileManager();
const term = new Term();

export default {
  namespaced: true,
  state: {
    ...term.state,
    ...processing.state,
    ...fileManager.state,
    ...state
  },
  actions,
  getters: {
    ...fileManager.getters,
    ...getters
  },
  mutations: {
    ...processing.mutations,
    ...fileManager.mutations,
    ...term.mutations,
    ...mutations
  }
};
