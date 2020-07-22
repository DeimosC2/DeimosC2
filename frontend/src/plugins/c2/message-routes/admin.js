import Vue from "vue";
import i18n from "../../../i18n";

export default class loot {
  processResponse(functionName, Data, Success) {
    this.logging(`c2VuePlugin::$c2:MessageRouter:Admin:${functionName} Success=${Success}`);
    this.logging(Data);

    if(functionName === "ListUsers") {
      this.store.commit("admin/setUsers", Data.map(user => {
        return {
          id: user.UserID,
          username: user.UserName,
          lastLogin: user.LastLogin,
          failedAttempts: user.FailedAttempts,
          isAdmin: user.Admin === "1"
        }
      }));
    }

    else if(functionName === "AddUser") {
      this.store.commit("admin/saving", false);
      Vue.prototype.$notify({
        type: Success ? "success" : "danger",
        message: Data.join(" ")
      });
      this.store.dispatch("admin/fetchUserList");
    }

    else if(functionName === "DeleteUser") {
      if (Success) {
        Vue.prototype.$notify({
          type: "success",
          message: i18n.t("notifications.user-was-deleted")
        });
        this.store.dispatch("admin/fetchUserList");
      }
    }

    else if(functionName === "ResetUser") {
      if (Success) {
        Vue.prototype.$notify({
          type: "success",
          message: i18n.t("notifications.user-was-reset")
        });
      }
    }

    else if(functionName === "EditUser") {
      if (Success) {
        Vue.prototype.$notify({
          type: "success",
          message: i18n.t("notifications.user-was-updated")
        });
        this.store.dispatch("admin/fetchUserList");
      }
    }

    else if(functionName === "ListBackupSchedule") {
      Data = Data.join(" ").split(",");
      Data.pop();
      this.store.commit("admin/updateBackupSettings", {time: Data.shift(), days: Data});
    }

    else if(functionName === "AppSettings") {
      if (Success) {
        Vue.prototype.$notify({
          type: "success",
          message: i18n.t("notifications.settings-was-updated")
        });
      }
      this.store.commit("admin/saving", false);
    }

    else if(functionName === "SetName") {
        Vue.prototype.$notify({
          type: Success ? "success" : "danger",
          message: Success ? i18n.t("notifications.agent-name-was-updated") :
            i18n.t("notifications.error-try-again")
        });
    }

    else if(functionName === "ListAppSettings") {
      this.store.commit("admin/setMFA", Data.MFASetting === "true");
      this.store.commit("admin/setPasswordLength", Data.PassLength[0]);
    }
  }

  constructor(store) {
    this.store = store;
    this.logging("c2VuePlugin::$c2:MessageRouter:Admin");
  }

  logging(message, level = "log") {
    Vue.prototype.$logging(message, this.store.state.debug, level);
  }
}
