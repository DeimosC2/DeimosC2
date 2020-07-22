// Make synchronous changes to state
export const setAgentTimeLine = (state, _var) => {
  // const arr = [];
  // _var.forEach(time => arr.push(Date.parse(time)));
  state.AgentTimeLine = {
    initialized: true,
    // data: arr,
    data: _var
  };
};

export const setAgentOSType = (state, _var) => {
  state.AgentOSType = {
    initialized: true,
    data: _var
  };
};

export const AgentByListener = (state, _var) => {
  state.AgentByListener = {
    initialized: true,
    data: _var
  };
};

export const PivotGraph = (state, _var) => {
  state.PivotGraph = {
    initialized: true,
    data: _var
  };
};

export const destroyPivotGraph = state => {
  state.PivotGraph = {
    initialized: false,
    data: []
  };
};

export const reinitialize = (state, _var) => {
  // set each metric to initialized value to 'false'
  Object.keys(state).forEach(metric => {
    state[metric].initialized = _var;
  });
};

export default {
  setAgentTimeLine,
  setAgentOSType,
  AgentByListener,
  PivotGraph,
  destroyPivotGraph,
  reinitialize
};
