import SideBar from "@/components/SidebarPlugin";
import Notify from "@/components/NotificationPlugin";
import ToggleButton from "vue-js-toggle-button";
import Tooltip from "vue-directive-tooltip";
import GlobalComponents from "./globalComponents";
import GlobalDirectives from "./globalDirectives";
import RTLPlugin from "./RTLPlugin";

import Vue from "vue";
import VueLocalStorage from "vue-localstorage";
Vue.use(VueLocalStorage);

const redTheme = () => import('@/assets/sass/red-theme.scss');
const greenTheme = () => import('@/assets/sass/green-theme.scss');

// css assets
if(Vue.localStorage.get("skin_theme")  === null) {
  Vue.localStorage.set("skin_theme", "red"); //set default theme
  redTheme();
} else {
  const skin_theme = Vue.localStorage.get("skin_theme");
  if(skin_theme === "red") {
    redTheme();
  } else if(skin_theme === "green") {
    greenTheme();
  } else {
    //fallback to red theme
    redTheme();
  }
}

import "@/assets/demo/demo.css"; // todo: get rid of demo.css

import "@/assets/css/nucleo-icons.css";
import "@/assets/css/fonts.css";
import "@fortawesome/fontawesome-free/css/all.css";
import "vue-directive-tooltip/dist/vueDirectiveTooltip.css";
import "element-ui/lib/theme-chalk/index.css";
import "codemirror/lib/codemirror.css";
import "codemirror/theme/base16-dark.css";

import "codemirror/mode/htmlembedded/htmlembedded.js";

export default {
  install(Vue) {
    Vue.use(GlobalComponents);
    Vue.use(GlobalDirectives);
    Vue.use(SideBar);
    Vue.use(Notify);
    Vue.use(RTLPlugin);
    Vue.use(ToggleButton);
    Vue.use(Tooltip);
  }
};
