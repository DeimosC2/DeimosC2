import Processing from "../../base/processing";

import state from "./state";
import actions from "./actions";
import getters from "./getters";
import mutations from "./mutations";

const processing = new Processing();

export default {
  namespaced: true,
  state: {
    ...processing.state,
    ...state
  },
  actions,
  getters,
  mutations: {
    ...processing.mutations,
    ...mutations
  }
};
