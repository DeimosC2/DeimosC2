/**
 * You can register global components here and use them as a plugin in your main Vue instance
 */
import { Tree } from "element-ui";
import { codemirror } from "vue-codemirror";
import {
  BaseInput,
  Card,
  BaseDropdown,
  BaseButton,
  BaseAlert,
  BaseTable,
  InfoTable
} from "../components/index";

const GlobalComponents = {
  install(Vue) {
    Vue.component(BaseInput.name, BaseInput);
    Vue.component(BaseAlert.name, BaseAlert);
    Vue.component(Card.name, Card);
    Vue.component(BaseDropdown.name, BaseDropdown);
    Vue.component(BaseButton.name, BaseButton);
    Vue.component(BaseTable.name, BaseTable);
    Vue.component(InfoTable.name, InfoTable);
    Vue.component(Tree.name, Tree);
    Vue.component("codemirror", codemirror);
  }
};

export default GlobalComponents;
