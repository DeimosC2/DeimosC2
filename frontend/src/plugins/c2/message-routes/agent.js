import Vue from "vue";
import router from "../../../router";
import {prepareForFileBrowser} from "./misc/mixin";

export default class agent {
  processResponse(functionName, Data, Success) {
    this.logging(`c2VuePlugin::$c2:MessageRouter:Agent:${functionName} Success=${Success}`);
    this.logging(Data);

    if(functionName === "New") {
      this.store.dispatch("agents/listAgents");
      this.store.dispatch("metrics/getAgentByOSType");
      this.store.dispatch("metrics/getAgentTimeline");
      this.store.dispatch("metrics/getAgentByListener");
    }

    else if(functionName === "List") {
      this.store.commit("agents/flushState");
      this.store.commit("agents/populateAgents", Data);
      this.store.commit("agents/initialize", true);
    }

    else if(functionName === "JobOutput") {
      if(Data.join(" ") === "Agent is being removed") {
        this.store.dispatch("agents/listAgents");
        router.push("/agents");
        return;
      }

      let generalBuffer = {...Data[0], ...Data[1]};

      this.logging(`Data = ${JSON.stringify(Data)}`);
      this.logging(`AgentKey = ${generalBuffer.AgentKey}`);
      this.logging(`Results = ${JSON.stringify(generalBuffer.Results)}`);
      this.logging(`generalBuffer = ${JSON.stringify(generalBuffer)}`);

      if (generalBuffer.JobName && generalBuffer.JobName === "fileBrowser") {
        const rowFiles = JSON.parse(`{${generalBuffer.Results}}`);
        rowFiles.CWD = rowFiles.CWD.slice(-1) === "/" ? rowFiles.CWD : rowFiles.CWD + "/";
        this.store.commit("agents/removeProcessingPath", rowFiles.CWD);
        this.store.commit("agents/setFiles", {
          parent: rowFiles.CWD,
          files: prepareForFileBrowser(rowFiles),
          uuid: generalBuffer.AgentKey
        });
      } else if (generalBuffer.JobName && generalBuffer.JobName === "download") {
        Vue.prototype.$notify({
          type: "success",
          message: `The file was downloaded: ${generalBuffer.Results}`
        });
      } else {
        this.store.commit("agents/jobOutput", generalBuffer);
      }
    }

    else if(functionName === "ModOutput") {
     let  generalBuffer = Data;
      this.logging(`AgentKey = ${generalBuffer.AgentKey}`);
      this.logging(`ModuleName = ${generalBuffer.ModuleName}`, this.store.state.debug);
      this.logging(`OutputType = ${generalBuffer.OutputType}`);
      this.logging(`Output = ${generalBuffer.Output}`);

      generalBuffer.Output = Buffer.from(generalBuffer.Output, "base64").toString(
        "ascii"
      );

      this.store.commit("agents/moduleOutput", generalBuffer);
    }

    else if(functionName === "HeartBeat") {
      this.store.dispatch("agents/heartBeat", Data.pop());
    }

    else if(functionName === "RemoveAgent") {
      this.store.dispatch("agents/listAgents");
    }

    else if(functionName === "ListComments") {
      this.store.commit("agents/addComments", Data);
    }

    else if(functionName === "AddComment") {
      this.store.dispatch("agents/fetchComments", Data.AgentKey);
      Vue.prototype.$notify({
        type: Success ? "success" : "danger",
        message: Data.Data
      });
    }
  }

  constructor(store) {
    this.store = store;
    this.logging("c2VuePlugin::$c2:MessageRouter:Agent");
  }

  logging(message, level = "log") {
    Vue.prototype.$logging(message, this.store.state.debug, level);
  }
}
