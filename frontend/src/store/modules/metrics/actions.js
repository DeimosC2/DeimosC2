import Vue from "vue";

export const getAgentByListener = () => {
  Vue.prototype.$c2.Metrics.GetAgentByListener();
};

export const getAgentByOSType = () => {
  Vue.prototype.$c2.Metrics.GetAgentOSType();
};

export const getAgentTimeline = () => {
  Vue.prototype.$c2.Metrics.GetAgentTimeline();
};

export const getPivotGraph = (context, _var) => {
  Vue.prototype.$c2.Metrics.GetPivotGraph(_var);
};

function getChildNode(array, children, context) {
  array.forEach(item => {
    const isRoot = item.IsElevated ? "root_" : "";

    let divImage = "";
    switch (item.OS) {
      case "linux":
        divImage = `/img/icons/${isRoot}linux.png`;
        break;
      case "windows":
        divImage = `/img/icons/${isRoot}windows.png`;
        break;
      default:
        divImage = `/img/icons/${isRoot}apple.png`;
        break;
    }
    const node = {
      innerHTML:
        `<div class="pivot-item"><img src="${divImage}"><br>` +
        `<a href='#' onclick='handlePivotNavigation(event,"${item.AgentKey}")' class="pivot-agent-link">` +
        `${item.AgentName}</a><br>Hostname: ${item.Hostname}<br>Local IP: ${item.LocalIP}</div>`,
      children: []
    };
    if (item.Linked) {
      node.children = getChildNode(item.Linked.Agents, [], context);
    }
    children.push(node);
  });
  return children;
}

export const PivotGraph = (context, _var) => {
  const graph = {
    text: {
      name: "parent" // that is hidden
    },
    children: []
  };

  _var.forEach(item => {
    if (item.Top) {
      const top = item;
      if (top.Agents.length) {
        const newNode = {
          innerHTML:
            `<div class="pivot-item"><img src="/img/login-logo.png" width="100" height="100"><br>` +
            `<a href='#' onclick='handlePivotNavigation(event,"${top.Listenerkey}", "listeners")' class="pivot-agent-link">` +
            `${top.Name}</a><br>Type: ${top.LType}<br>Port: ${top.Port}</div>`,
          children: getChildNode(top.Agents, [], context)
        };
        graph.children.push(newNode);
      }
    }
  });
  context.commit("PivotGraph", graph);
};

export default {
  getAgentByListener,
  getAgentByOSType,
  getAgentTimeline,
  getPivotGraph,
  PivotGraph
};
