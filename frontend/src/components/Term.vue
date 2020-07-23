<template>
  <Panel :title="$t('agents.terminal')">
    <div class="term" v-if="showSwitches">
      <div class="col-lg-12">
        <div class="row">
          <div class="col-4">
            <base-dropdown>
              <template slot="title-container">
                Shell:
                <span class="btn btn-link dropdown-toggle">
                  {{ getShell }} <i class="fas fa-caret-down"></i>
                </span>
              </template>

              <li v-for="item in agent.Shellz" :key="item">
                <a href="#" class="nav-item dropdown-item" @click.prevent="updateShell(item)">
                  {{ getShellShort(item) }}
                </a>
              </li>
            </base-dropdown>
          </div>
          <div class="col-4">
            Switches: <input type="text" v-model="switches" class="switches" />
          </div>
        </div>
      </div>
    </div>
    <div class="term-form">
      <div :ref="ref"></div>
    </div>
  </Panel>
</template>

<script>
import { mapState, mapMutations } from "vuex";

import jQuery from "jquery";
// eslint-disable-next-line no-unused-vars
import terminal from "jquery.terminal";

import parser from "yargs-parser";

import "jquery.terminal/css/jquery.terminal.css";

import _ from "lodash";
import Panel from "./Panel";

const $ = jQuery;

export default {
  name: "Term",
  components: {
    Panel
  },
  props: {
    agent: {
      Type: Object,
      Required: true
    },
    module: {
      Type: String,
      Required: true
    },
    commands: {
      Required: true
    },
    showSwitches: {
      type: Boolean,
      default: true
    }
  },
  data: () => ({
    executed: new Set(),
    prompt: "DC2>",
    shell: null,
    switches: null,
    commandList: null,
    jQueryTerm: null,
    default: {
      switches: {
        "cmd.exe": "/c",
        "powershell.exe": "-c",
        bash: "-c",
        sh: "-c",
        zsh: "-c"
      },
      shell: {
        windows: "cmd.exe",
        linux: "bash",
        darwin: "zsh"
      }
    }
  }),
  computed: {
    ...mapState({
      debug: "debug",
      terminal(state) {
        return this.getState(state, this.module).terminal;
      },
      output: state => state.term.output
    }),
    title() {
      return `${this.agent.Username} @ ${this.agent.Hostname}`;
    },
    user() {
      return this.agent.Username.split("\\")[1];
    },
    ref() {
      return `terminal_${this.agent.Key.replace(/-/g, "_")}`;
    },
    getShell() {
      return this.getShellShort(this.shell) || "ERROR";
    }
  },
  watch: {
    output(newValue) {
      if (newValue) {
        this.jQueryTerm.echo(newValue);
        this.$store.commit("term/setOutput", "");
      }
    },
    switches(newValue) {
      this.commands.$setSwitches(newValue);
    }
  },
  methods: {
    setShell(shell) {
      this.shell = shell;
      this.setPrompt();
      this.setSwitches();
      this.commands.$setCMDShell(shell);
    },
    setSwitches(shell) {
      this.switches = this.default.switches[shell];
    },
    setPrompt(shell) {
      const mapping = {
        "cmd.exe": "C:\\> ",
        "powershell.exe": "PS C:\\> ",
        bash: "# ",
        sh: "# ",
        zsh: "zsh~ "
      };
      this.prompt = mapping[shell];
      if (this.jQueryTerm) {
        this.jQueryTerm.set_prompt(this.prompt);
      }
    },
    getState(rootState, modulePath) {
      const modules = modulePath.split("/");
      let state = rootState;
      for (let i = 0; i < modules.length; i += 1) {
        state = state[modules[i]];
      }
      return state;
    },
    updateShell(item) {
      const shell = this.getShellShort(item);
      this.setShell(shell);
      this.setSwitches(shell);
      this.setPrompt(shell);
    },
    getShellShort(item) {
      if (item) {
        const split = item.split(/([/\\])/);
        return split[split.length - 1];
      }
      return item;
    },
    ...mapMutations({
      setAgentKey: "term/setAgentKey",
      setCurrentModule: "term/setCurrentModule"
    })
  },
  mounted() {
    this.$logging("Term::mounted()", this.debug);
    if (this.showSwitches) {
      let shell = this.agent.Shellz[0];
      if (_.isEmpty(shell)) {
        shell = this.default.shell[this.agent.OS];
      } else {
        shell = this.getShellShort(shell);
      }

      this.setShell(shell);
      this.setSwitches(shell);
      this.setPrompt(shell);
    }
    this.commandList = this.commands.$getCommands();

    this.setAgentKey(this.agent.Key);
    this.setCurrentModule(this.module);

    const termDiv = this.$refs[this.ref];
    const vue = this;

    this.jQueryTerm = $(termDiv).terminal(
      // eslint-disable-next-line func-names
      function(commandString) {
        if (commandString !== "") {
          const { commands, commandList } = this.settings().extra;
          let result = null;
          try {
            const command = commandString.split(" ")[0];
            if (commandList.includes(command)) {
              const allArgs = [];
              const rowCommands = commandString.split("|");
              rowCommands.forEach(singleCommand => {
                const args = parser(singleCommand, {
                  configuration: {
                    "short-option-groups": false
                  }
                });
                Object.keys(args).forEach(item => {
                  if (item !== "_") {
                    const param = args[item] !== true ? `-${item} ${args[item]}` : `-${item}`;
                    args._.push(param);
                  }
                });
                args._.push("|");
                allArgs.push(args._);
              });
              allArgs[allArgs.length - 1].pop(); // remove last |
              result = commands[command]({ _: _.flatten(allArgs) });
            }

            if (result !== null) {
              this.echo(result);
            } else {
              this.error(vue.$t("term.invalid-command"));
            }
          } catch (e) {
            console.error("Term:: Error = ", e);
            this.error(e);
          }
        } else {
          this.echo("");
        }
      },
      {
        greetings: "Commence Pwnage...",
        autocompleteMenu: true,
        completion: this.commandList,
        // height: 300, // need to find a way to "fill" to the bottom of the window
        prompt: this.prompt,
        memory: true, // does not use cookies or localstorage, all in memory
        extra: {
          parser,
          commandList: this.commandList,
          commands: this.commands
        }
      }
    );
  }
};
</script>
