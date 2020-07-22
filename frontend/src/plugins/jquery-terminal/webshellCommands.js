import Vue from "vue";
import store from "@C2/store";

export default class commands {
  /* eslint-disable lines-between-class-members */
  #debug = store.state.debug;
  $logging = Vue.prototype.$logging;
  /* eslint-enable lines-between-class-members */

  #usage = {
    cmd: {
      help: `  Usage: cmd <command>
  Execute a CMD (or shell) command through the web shell`
    },
    power: {
      help: `  Usage: power <command>
  Execute a PowerShell command through a web shell (if Windows)`
    }
  };

  constructor(uuid) {
    this.uuid = uuid;
  }

  $getCommands() {
    // trims out all class properties that are not commands
    const props = Object.getOwnPropertyNames(Object.getPrototypeOf(this));
    props.shift();
    const indexStart = props.findIndex(i => i[0] !== "$");
    return props.slice(indexStart, props.length);
  }

  cmd(args) {
    const data = {
      UUID: this.uuid,
      Options: args._
    };
    return store.dispatch("webShells/sendJob", data);
  }

  power(args) {
    const data = {
      UUID: this.uuid,
      Options: args._
    };
    return store.dispatch("webShells/sendJob", data);
  }
}
