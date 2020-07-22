import Processing from "../../base/processing";
import FileManager from "../../base/fileManager";

import state from "./state";
import actions from "./actions";
import getters from "./getters";
import mutations from "./mutations";

const processing = new Processing();
const fileManager = new FileManager();

export default {
  namespaced: true,
  state: {
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
    ...mutations
  }
};
