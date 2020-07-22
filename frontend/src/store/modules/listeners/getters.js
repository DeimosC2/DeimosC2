// export const getFunc = (state) => {
//   Do stuff;
//   return stuff;
// };

export const getListeners = state => state.listeners;
// eslint-disable-next-line max-len
export const getListenerByName = state => name =>
  state.listeners.find(listener => listener.Name === name);
// eslint-disable-next-line max-len
export const getListenerByKey = state => key =>
  state.listeners.find(listener => listener.Key === key);

export default {
  getListeners,
  getListenerByName,
  getListenerByKey
};
