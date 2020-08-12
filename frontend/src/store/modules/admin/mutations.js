export const setUsers = (state, _var) => {
  state.users = _var;
};

export const updateBackupSettings = (state, _var) => {
  state.backupSettings.days = _var.days.map(s => s.trim());
  const time = _var.time.split(":");
  state.backupSettings.hours = time.length === 2 ? time[0].trim() : 0;
  state.backupSettings.minutes = time.length === 2 ? time[1].trim() : 0;
};

export const setMFA = (state, _var) => {
  state.mfa = _var;
};

export const setPasswordLength = (state, _var) => {
  state.passlength = _var;
};

export const logs = (state, _var) => {
  state.logs = _var;
};

export default {
  setUsers,
  updateBackupSettings,
  setMFA,
  setPasswordLength,
  logs
};
