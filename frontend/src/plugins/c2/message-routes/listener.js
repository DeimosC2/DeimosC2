import Vue from "vue";
import {saveAsFile} from "./misc/mixin";
import i18n from "../../../i18n";

export default class listener {
  processResponse(functionName, Data, Success) {
    this.logging(`c2VuePlugin::$c2:MessageRouter:Listener:${functionName} Success=${Success}`);
    this.logging(Data);

    if(functionName === "Add") {
      this.store.commit("listeners/saving", false);
      if (Success) {
        this.store.commit("listeners/createListener", Data);
      }
    }

    else if(functionName === "List") {
      this.store.commit("listeners/flushState");
      Data.map(listener => {
        this.store.commit("listeners/createListener", listener);
      });
      this.store.commit("listeners/initialize", true);
    }

    else if(functionName === "Edit") {
      this.store.commit("listeners/saving", false);
      if (Success) {
        this.store.commit("listeners/editListener", Data);
      }
    }

    else if(functionName === "Kill") {
      if (Success) {
        this.store.commit("listeners/killListener", Data);
      }
    }

    else if(functionName === "Error") {
      this.store.commit("listeners/saving", false);
      this.store.commit("listeners/saveError", Data);
    }

    else if(functionName === "GetListenerPrivateKey") {
      saveAsFile(Data.PrivateKey, "privateKey.pem", "text/html");
    }

    else if(functionName === "AgentCreate") {
      this.store.dispatch("agents/listAgents");
      Vue.prototype.$notify({
        type: "success",
        message: i18n.t("notifications.agents-was-created") + ` : ${Data.File}`
      });
    }

    else if(functionName === "GetCompiled") {
      this.store.commit("listeners/getCompiled", Data);
    }
  }

  constructor(store) {
    this.store = store;
    this.logging("c2VuePlugin::$c2:MessageRouter:Listener");
  }

  logging(message, level = "log") {
    Vue.prototype.$logging(message, this.store.state.debug, level);
  }
}
