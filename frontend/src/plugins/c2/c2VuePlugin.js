import Vue from "vue";
import VueNativeSock from "vue-native-websocket";
import i18n from "../../i18n";

import listener from "./message-routes/listener";
import agent from "./message-routes/agent";
import metrics from "./message-routes/metrics";
import webshell from "./message-routes/webshell";
import loot from "./message-routes/loot";
import admin from "./message-routes/admin";
import archive from "./message-routes/archive";

const C2VuePlugin = {
  // eslint-disable-next-line no-shadow
  install(Vue, options) {
    if (options.store) {
      this.store = options.store;
    }

    Vue.use(VueNativeSock, `//${window.location.host}/ws`, {
      store: this.store,
      connectManually: true,
      format: "json",
      reconnection: true,
      reconnectionAttempts: 2,
      reconnectionDelay: 1000
    });

    // eslint-disable-next-line no-param-reassign
    Vue.prototype.$c2 = {
      MessageRouter: msg => {
        const {Type, FunctionName} = msg;
        let {Data, Success} = msg;
        this.logging(msg, "warn");
        this.logging(`c2VuePlugin::$c2:MessageRouter:msg.stringify=${JSON.stringify(msg)}`);
        this.logging(`c2VuePlugin::$c2:MessageRouter:Type=${Type}`);
        this.logging(`c2VuePlugin::$c2:MessageRouter:FunctionName=${FunctionName}`);

        try {
          Data = JSON.parse(Data);
        } catch (error) {
          this.logging(`Error Caught: ${error}`, "warn");
          Data = Data.split(" ");
        }

        Success = Boolean(Success);

        if(Type === "MFA Setup Required") {
          this.store.dispatch("setMFARequired");
        }
        else if(Type === "MFA Required") {
          this.store.dispatch("setMFARequired");
        }
        else if(Type === "QRCode") {
          this.store.commit("setQRCode", Data);
        }
        else if(Type === "ChangePassword") {
          this.store.commit("forceToChangePassword", true);
        }
        else if(Type === "User") {
          this.store.commit("setUser", Data);
        }
        else if(Type === "Cookie") {
          if (!Success) {
            this.logging("login failed, redirect to login page", "warn");
            window.location.href = "/";
          }
        } else {

          let responseParser = null;
          if(Type === "Listener") {
            responseParser = new listener(this.store);
          }
          else if(Type === "Agent") {
            responseParser = new agent(this.store);
          }
          else if(Type === "Metrics") {
            responseParser = new metrics(this.store);
          }
          else if(Type === "WebShell") {
            responseParser = new webshell(this.store);
          }
          else if(Type === "Loot") {
            responseParser = new loot(this.store);
          }
          else if(Type === "Admin") {
            responseParser = new admin(this.store);
          }
          else if(Type === "Archive") {
            responseParser = new archive(this.store);
          }
          else {
            this.logging(`c2VuePlugin::$c2:MessageRouter: Unknown Type=${Type}`, "warn");
          }

          if(responseParser) {
            responseParser.processResponse(FunctionName, Data, Success);
          }
        }
      },

      Listener: {
        AddListener: data => {
          this.sendRequest("Listener", "Add", data, this.store);
        },
        EditListener: data => {
          this.sendRequest("Listener", "Edit", data, this.store);
        },
        GetListeners: () => {
          this.sendRequest("Listener", "List", {}, this.store);
        },
        KillListener: data => {
          this.sendRequest("Listener", "Kill", {Key: data.Key}, this.store);
        },
        GetListenerPrivateKey: data => {
          this.sendRequest("Listener", "GetListenerPrivateKey", {Key: data.Key}, this.store);
        },
        CreateAgent: data => {
          this.sendRequest("Listener", "CreateAgent", data, this.store);
        },
        GetCompiledAgents: data => {
          this.sendRequest("Listener", "GetCompiled", data, this.store);
        }
      },

      Agent: {
        GetAgents: () => {
          this.sendRequest("Agent", "List", {}, this.store);
        },
        register: AgentKey => {
          this.sendRequest("Register", "Agent", {AgentKey}, this.store);
        },
        deregister: AgentKey => {
          this.sendRequest("Deregister", "Agent", {AgentKey}, this.store);
        },
        sendJob: (AgentKey, moduleName, cmd) => {
          const rawData = {AgentKey, JobType: moduleName, Arguments: cmd};
          this.sendRequest("Agent", "Job", rawData, this.store);

          this.logging(`c2VuePlugin::$c2:Agent:sendJob:AgentKey="${AgentKey}"`);
          this.logging(`c2VuePlugin::$c2:Agent:sendJob:moduleName="${moduleName}"`);
          this.logging(`c2VuePlugin::$c2:Agent:sendJob:cmd="${cmd}"`);
          // {"Type":"Agent",
          //  "FunctionName":"Job",
          //  "Data":
          //    "{\"AgentKey\":\"f22eb334-e02e-4b89-9565-a782109b84a6\",
          //    \"JobType\":\"module\",
          //    \"Arguments\":[\"moduleName\"]
          //    }"
          //  }
          return `Job ${moduleName} Sent...`;
        },
        sendModule: data => {
          this.sendRequest("Agent", "Module", data, this.store);
          return `Module ${data.ModuleName} Sent...`;
        },
        removeAgent: data => {
          this.sendRequest("Agent", "RemoveAgent", {AgentKey: data}, this.store);
        },
        fetchComments: data => {
          this.sendRequest("Agent", "ListComments", {AgentKey: data}, this.store);
        },
        sendComment: data => {
          this.sendRequest("Agent", "AddComment", data, this.store);
        },
        setName: data => {
          this.sendRequest("Agent", "SetName",
            {AgentKey: data.Key, AgentName: data.Name},
            this.store);
        }
      },

      Metrics: {
        GetAgentTimeline: () => {
          this.sendRequest("Metrics", "AgentTimeline", "{}", this.store);
        },
        GetAgentOSType: () => {
          this.sendRequest("Metrics", "AgentOSType", "{}", this.store);
        },
        GetAgentByListener: () => {
          this.sendRequest("Metrics", "AgentByListener", "{}", this.store);
        },
        GetPivotGraph: (listener) => {
          const data = listener ? {Listener: listener} : {};
          this.sendRequest("Metrics", "PivotGraph", data, this.store);
        }
      },

      WebShell: {
        GenerateShell: type => {
          this.sendRequest("WebShell", "GenerateShell", {type}, this.store);
        },
        InitWebShell: data => {
          this.sendRequest("WebShell", "Init", data, this.store);
        },
        DeleteWebShell: data => {
          this.sendRequest("WebShell", "DeleteShell", data, this.store);
        },
        FileBrowser: data => {
          this.sendRequest("WebShell", "FileBrowser", data, this.store);
        },
        FileEditor: data => {
          this.sendRequest("WebShell", "FileEditor", data, this.store);
        },
        FileUpload: data => {
          this.sendRequest("WebShell", "FileUpload", data, this.store);
        },
        ListShells: () => {
          this.sendRequest("WebShell", "List", "{}", this.store);
        },
        sendJob: data => {
          this.sendRequest("WebShell", "ExecuteCommand", data, this.store);
          return `Command ${data.Options.join(" ")} Sent...`;
        }
      },

      Loot: {
        ListLoot: () => {
          this.sendRequest("Loot", "List", "{}", this.store);
        },
        ListLootFiles: data => {
          this.sendRequest("Loot", "ListLootFiles", {path: data}, this.store);
        },
        ListAgentLoot: data => {
          this.sendRequest("Loot", "ListAgentLoot", {agentKey: data}, this.store);
        },
        AddLootManually: data => {
          this.sendRequest("Loot", "Add", data, this.store);
        },
        AddPasswordHash: data => {
          this.sendRequest("Loot", "EditPass", data, this.store);
        },
      },

      Admin: {
        ListUsers: () => {
          this.sendRequest("Admin", "ListUsers", {}, this.store);
        },
        AddUser: (data) => {
          this.sendRequest("Admin", "AddUser", data, this.store);
        },
        DeleteUser: (data) => {
          this.sendRequest("Admin", "DeleteUser", data, this.store);
        },
        EditUser: (data) => {
          this.sendRequest("Admin", "EditUser", data, this.store);
        },
        ResetUser: (data) => {
          this.sendRequest("Admin", "ResetUser", data, this.store);
        },
        ListAppSettings: (data) => {
          this.sendRequest("Admin", "ListAppSettings", {}, this.store);
        },
        UpdateAppSettings: (data) => {
          this.sendRequest("Admin", "AppSettings", data, this.store);
        },
        ListBackupSchedule: () => {
          this.sendRequest("Admin", "ListBackupSchedule", {}, this.store);
        }
      },

      Archive: {
        SetSchedule: (data) => {
          this.sendRequest("Archive", "SetSchedule", data, this.store);
        },
        DownloadBackup: () => {
          this.sendRequest("Archive", "Backup", {"Backup":true}, this.store);
        },
        EndGame: () => {
          this.sendRequest("Archive", "EndGame", {"Backup":false}, this.store);
        }
      },

      Token: {
        SendToken: (data) => {
          this.sendRequest("Token", "", {Token: data}, this.store);
        }
      },

      Reinitialize: () => {
        this.logging("c2VuePlugin::$c2:Reinitialize:listeners");
        this.store.commit("listeners/initialize", false);
        this.logging("c2VuePlugin::$c2:Reinitialize:agents");
        this.store.commit("agents/initialize", false);
        this.logging("c2VuePlugin::$c2:Reinitialize:metrics");
        this.store.commit("metrics/reinitialize", false);
      }
    };
  },

  logging(message, level = "log") {
    Vue.prototype.$logging(message, this.store.state.debug, level);
  },

  sendRequest(Type, FunctionName, rowData, store) {
    this.logging(`c2VuePlugin::$c2:${Type}:${FunctionName}:data=${rowData}`, "warn");
    this.logging(rowData, "warn");

    const Data = rowData;
    const msg = {Type, FunctionName, Data};

    this.logging(`c2VuePlugin::$c2:${Type}:${FunctionName}:msg="${JSON.stringify(msg)}"`);

    try {
      Vue.prototype.$socket.sendObj(msg);
    } catch (e) {
      this.logging(e.message, "error");
      store.dispatch("clearSaving");
      Vue.prototype.$notify({type: "danger", message: i18n.t("notifications.socket-error")});
    }
  }
};

export default C2VuePlugin;
