class Term {
  constructor() {
    this.state = {
      terminal: {
        buffer: {
          // Key is UUID
          // value is array of outputs
        }
      }
    };

    this.mutations = {
      jobOutput(state, _var) {
        try {
          state.terminal.buffer[_var.AgentKey].push(_var.Results);
        } catch {
          state.terminal.buffer[_var.AgentKey] = [_var.Results];
        }
      },

      moduleOutput(state, _var) {
        const msg = `${_var.OutputType}:${_var.Output}`;

        try {
          state.terminal.buffer[_var.AgentKey].push(msg);
        } catch {
          state.terminal.buffer[_var.AgentKey] = [msg];
        }
      }
    };

    this.actions = {};
  }
}

export default Term;
