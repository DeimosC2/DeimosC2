import Vue from "vue";

export const fetchUserList = (context, _var) => {
  Vue.prototype.$c2.Admin.ListUsers(_var);
};

export const addUser = (context, _var) => {
  context.commit("saving", true);
  Vue.prototype.$c2.Admin.AddUser({ Options: [_var.login, _var.password, _var.admin ? "1" : "0"] });
};

export const deleteUser = (context, _var) => {
  Vue.prototype.$c2.Admin.DeleteUser({ Options: [_var] });
};

export const resetUser = (context, _var) => {
  Vue.prototype.$c2.Admin.ResetUser({ Options: [_var] });
};

export const editUser = (context, _var) => {
  Vue.prototype.$c2.Admin.EditUser({
    UserID: _var.id,
    username: _var.username,
    admin: _var.isAdmin ? "1" : "0",
    password: _var.password
  });
};

export const editPassword = (context, _var) => {
  Vue.prototype.$axios
    .post("/change.pass", _var)
    .then(() => {
      context.commit("saving", false);
      context.commit("forceToChangePassword", false, { root: true });
      Vue.prototype.$notify({
        type: "success",
        message: "Please login again now with the new password"
      });
      Vue.prototype.$axios.get("/log.out").then(() => {
        window.location.href = "/login";
      });
    })
    .catch(error => {
      context.commit("saving", false);
      const message = error.response ? error.response.data : error.message;
      context.commit("saveError", message);
    });
};

export const listBackupSchedule = () => {
  Vue.prototype.$c2.Admin.ListBackupSchedule();
};

export const updateBackupSchedule = (context, _var) => {
  Vue.prototype.$c2.Archive.SetSchedule(_var);
};

export const appSettings = () => {
  Vue.prototype.$c2.Admin.ListAppSettings();
};

export const updateAppSettings = (context, _var) => {
  Vue.prototype.$c2.Admin.UpdateAppSettings({ Options: [`${_var.mfa}`, _var.passlength] });
};

export const createAccount = (context, _var) => {
  Vue.prototype.$axios
    .post("/set.up", _var)
    .then(() => {
      window.location.href = "/login";
    })
    .catch(error => {
      Vue.prototype.$notify({ type: "danger", message: error.message });
    });
};

export const downloadBackup = () => {
  Vue.prototype.$c2.Archive.DownloadBackup();
};

export const endGame = () => {
  Vue.prototype.$c2.Archive.EndGame();
};

export const getLogs = (context, _var) => {
  Vue.prototype.$c2.LogViewer.fetchLogs(_var);
};

export default {
  fetchUserList,
  addUser,
  deleteUser,
  resetUser,
  editUser,
  editPassword,
  listBackupSchedule,
  updateBackupSchedule,
  appSettings,
  updateAppSettings,
  downloadBackup,
  endGame,
  createAccount,
  getLogs
};
