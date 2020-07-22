import Vue from "vue";
import {download} from "./misc/mixin";
import i18n from "../../../i18n";

export default class loot {
  processResponse(functionName, Data, Success) {
    this.logging(`c2VuePlugin::$c2:MessageRouter:Archive:${functionName} Success=${Success}`);
    this.logging(Data);

    if(functionName === "SetSchedule") {
      if (Success) {
        Vue.prototype.$notify({
          type: "success",
          message:  i18n.t("notifications.backup-settings-was-updated")
        });
      }
    }

    else if(functionName === "Backup") {
      download(`${Data}`);
    }
  }

  constructor(store) {
    this.store = store;
    this.logging("c2VuePlugin::$c2:MessageRouter:Archive");
  }

  logging(message, level = "log") {
    Vue.prototype.$logging(message, this.store.state.debug, level);
  }
}
