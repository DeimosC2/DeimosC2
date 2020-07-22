export const setLoot = (state, _var) => {
  state.loot = _var;
};

export const clearLootCache = state => {
  state.loot = [];
};

export default {
  setLoot,
  clearLootCache
};
