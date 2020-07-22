import Vue from "vue";
import i18n from "../../../i18n";
import {prepareForFileBrowser, download} from "./misc/mixin";

export default class webshell {
  processResponse(functionName, Data, Success) {
    this.logging(`c2VuePlugin::$c2:MessageRouter:WebShell:${functionName} Success=${Success}`);
    this.logging(Data);

    if(functionName === "GenerateShell") {
      this.store.commit("webShells/saving", false);
      if (Success) {
        this.store.commit("webShells/addGeneratedFile", {
          name: Data.Path.split("/").pop(),
          file: Data.Path
        });
        window.open(Data.Path);
      } else {
        this.store.commit("listeners/saveError", "Error: Unable to generate webshell");
      }
    }

    else if(functionName === "Init") {
      this.store.commit("webShells/saving", false);
      if (Success) {
        this.store.dispatch("webShells/listShells");
      } else {
        this.store.commit("webShells/saveError", "Error: Unable to add webshell");
      }
    }

    else if(functionName === "DeleteShell") {
      if (Success) {
        this.store.dispatch("webShells/listShells");
      } else {
        Vue.prototype.$notify({type: "danger", message: i18n.t("notifications.unable-to-delete-webshell")});
      }
    }

    else if(functionName === "FileBrowser") {
      if (Data.Method === "") {
        const UUID = Data.UUID;
        // list files under the directory
        Data = Data.initData[0];
        Data.CWD = Data.CWD.slice(-1) === "/" ? Data.CWD : Data.CWD + "/";
        this.store.commit("webShells/removeProcessingPath", Data.CWD);
        this.store.commit("webShells/setFiles", {
          parent: Data.CWD,
          files: prepareForFileBrowser(Data),
          uuid: UUID
        });
      } else if (Data.Method === "remove") {
        // it is `remove`  "initData": [0] - can't remove  "initData": [1] - success
        if (Data.initData[0] === 0) {
          Vue.prototype.$notify({
            type: "danger",
            message: i18n.t("notifications.cannot-remove-the-folder")
          });
        }
      } else if (Data.Method === "mkdir") {
        this.store.commit("webShells/fileSaving", false);
      } else if (Data.Method === "download") {
        download(Data.initData.join(" "));
      }
      if (!Success) {
        Vue.prototype.$notify({type: "danger", message: i18n.t("notifications.try-again")});
      }
    }

    else if(functionName === "FileEditor") {
      this.store.commit("webShells/fileFetching", false);
      this.store.commit("webShells/fileSaving", false);
      if (Success) {
        this.store.commit("webShells/fileSaveResult", "Success!");
        // Todo: it should be different function name for read and write
        // because there is no difference between response on write and reading empty file
        if (Data.length && Data[0] !== "") {
          this.store.commit("webShells/editFile", Data.join(" "));
        }
      } else {
        this.store.commit("webShells/fileSaveResult", "Error: Unable to save!");
      }
    }

    else if(functionName === "List") {
      this.store.commit("webShells/populateWebShells", Data);
    }

    else if(functionName === "FileUpload") {
      this.store.commit("webShells/fileSaving", false);
    }

    else if(functionName === "ExecuteCommand") {
      this.store.commit("webShells/jobOutput", {AgentKey: "webshell", Results: Data.join(" ")});
    }
  }

  constructor(store) {
    this.store = store;
    this.logging("c2VuePlugin::$c2:MessageRouter:WebShell");
  }

  logging(message, level = "log") {
    Vue.prototype.$logging(message, this.store.state.debug, level);
  }
}
