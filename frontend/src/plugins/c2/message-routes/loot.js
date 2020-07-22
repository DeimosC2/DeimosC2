import Vue from "vue";
import {prepareForFileBrowser} from "./misc/mixin";

export default class loot {
  processResponse(functionName, Data, Success) {
    this.logging(`c2VuePlugin::$c2:MessageRouter:Loot:${functionName} Success=${Success}`);
    this.logging(Data);

    if(functionName === "List") {
      if (Data) {
        this.store.commit("loot/setLoot", Data.map(item => {
          return {
            id: "",
            username: item.User,
            password: item.Password,
            hash: item.Hash,
            credType: item.Creds,
            isWebshell: item.SSP !== "",
            host: item.Host,
            domain: item.Domain
          }
        }));
      }
    }

    else if(functionName === "ListAgentLoot") {
      if (Data) {
        this.store.commit("loot/setLoot", Data.map(item => {
          return {
            id: "",
            username: item.User,
            password: item.Password,
            hash: item.Hash,
            credType: item.Creds,
            isWebshell: item.SSP !== "",
            host: item.Host,
            domain: item.Domain
          }
        }));
      }
    }

    else if(functionName === "ListLootFiles") {
      Data.CWD = Data.Path;
      this.store.commit("loot/removeProcessingPath", Data.CWD);
      this.store.commit("loot/setFiles", {
        parent: Data.Path === "/looted/" ? "./" : Data.Path,
        files: prepareForFileBrowser(Data),
        uuid: "loot"
      });
    }

    else if(functionName === "Add") {
      this.store.dispatch("loot/listLoots");
      this.store.commit("loot/saving", false);
      Vue.prototype.$notify({
        type: Success ? "success" : "danger",
        message: Data.join(" ")
      });
    }

    else if(functionName === "EditPass") {
      this.store.commit("loot/saving", false);
      if (!Success) {
        this.store.commit("loot/saveError", "Error: Unable to add password");
      }
    }
  }

  constructor(store) {
    this.store = store;
    this.logging("c2VuePlugin::$c2:MessageRouter:Loot");
  }

  logging(message, level = "log") {
    Vue.prototype.$logging(message, this.store.state.debug, level);
  }
}
