import Vue from "vue";

export default class metrics {
  processResponse(functionName, Data, Success) {
    this.logging(`c2VuePlugin::$c2:MessageRouter:Metrics:${functionName} Success=${Success}`);
    this.logging(Data);

    if(functionName === "AgentTimeline") {
      this.store.commit("metrics/setAgentTimeLine", Data);
    }

    else if(functionName === "AgentOSType") {
      this.store.commit("metrics/setAgentOSType", Data);
    }

    else if(functionName === "AgentByListener") {
      this.store.commit("metrics/AgentByListener", Data);
    }

    else if(functionName === "PivotGraph") {
      this.store.dispatch("metrics/PivotGraph", Data);
    }
  }

  constructor(store) {
    this.store = store;
    this.logging("c2VuePlugin::$c2:MessageRouter:Metrics");
  }

  logging(message, level = "log") {
    Vue.prototype.$logging(message, this.store.state.debug, level);
  }
}
