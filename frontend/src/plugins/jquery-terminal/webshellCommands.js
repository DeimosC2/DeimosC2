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
  Execute a CMD command through the web shell`
    },
    shell: {
      help: `  Usage: cmd <command>
  Execute a shell command through the web shell`
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
    let action = args._.shift();
    const data = {
      UUID: this.uuid,
      Options: [action, args._.join(" ")]
    };
    return store.dispatch("webShells/sendJob", data);
  }

  shell(args) {
    let action = args._.shift();
    const data = {
      UUID: this.uuid,
      Options: [action, args._.join(" ")]
    };
    return store.dispatch("webShells/sendJob", data);
  }

  power(args) {
    let action = args._.shift();
    const data = {
      UUID: this.uuid,
      Options: [action, args._.join(" ")]
    };
    return store.dispatch("webShells/sendJob", data);
  }
}
