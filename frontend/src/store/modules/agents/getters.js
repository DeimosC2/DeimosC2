// 'state' references the module state, not the global state
export const getAgents = state => state.agents;

export const getAgentByKey = state => key => state.agents.find(agent => agent.Key === key);

export const isRoot = state => key => {
  const agent = state.agents.find(item => item.Key === key);
  if (agent) return agent.IsElevated;
  return false;
};

export default {
  getAgents,
  getAgentByKey,
  isRoot
};
