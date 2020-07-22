import Vue from "vue";
import _ from "lodash";

export const listLoots = () => {
  Vue.prototype.$c2.Loot.ListLoot();
};

export const listLootFiles = (store, agentKey) => {
  Vue.prototype.$c2.Loot.ListLootFiles(agentKey);
};

export const listAgentLoot = (store, agentKey) => {
  Vue.prototype.$c2.Loot.ListAgentLoot(agentKey);
};

export const addLootManually = (store, data) => {
  Vue.prototype.$c2.Loot.AddLootManually(data);
};

export const addPasswordHash = (store, data) => {
  Vue.prototype.$c2.Loot.AddPasswordHash(data);
};

export const fileBrowser = (context, _var) => {
  const agent = _var.startPoint === "." ? "" : _.trim(_var.startPoint.replace("/looted", ""), "/");
  Vue.prototype.$c2.Loot.ListLootFiles(agent);
};

export const downloadFile = (context, _var) => {
  window.open(_var.path);
};

export default {
  listLoots,
  listLootFiles,
  listAgentLoot,
  addLootManually,
  addPasswordHash,
  fileBrowser,
  downloadFile
};
