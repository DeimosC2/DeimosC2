/*
 =========================================================
 * Vue Black Dashboard - v1.1.0
 =========================================================

 * Product Page: https://www.creative-tim.com/product/black-dashboard
 * Copyright 2018 Creative Tim (http://www.creative-tim.com)

 =========================================================

 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

 */
import Vue from "vue";
import VueRouter from "vue-router";
import RouterPrefetch from "vue-router-prefetch";
import axios from "axios";
import Vuelidate from "vuelidate";

import Tooltip from "vue-directive-tooltip";
import moment from "moment";
import App from "./App";
import router from "./router/index";

import BlackDashboard from "./plugins/blackDashboard";
import i18n from "./i18n";
import C2Plugin from "./plugins/c2/c2VuePlugin";

import "vue-directive-tooltip/dist/vueDirectiveTooltip.css";

import store from "./store/index";

Vue.use(BlackDashboard);
Vue.use(VueRouter);
Vue.use(RouterPrefetch);
Vue.use(Vuelidate);
Vue.use(C2Plugin, { store });

Vue.prototype.$logging = (message, toLog = true, level = "log") => {
  if (toLog) console[level](message);
};

Vue.prototype.$axios = axios;

window.handlePivotNavigation = function handlePivotNavigation(event, UUID, type = "agents") {
  event.preventDefault();
  router.push(`/${type}/${UUID}`);
};

Vue.use(Tooltip);
Vue.filter("datetime", function(value) {
  if (moment(value).isValid()) {
    const date = moment(value);
    return date.format("YYYY-MM-DD hh:mm:ss");
  }
  if (value.length > 19) {
    // moment cannot parse RFC3339Nano because Go has invalid format for that
    // https://github.com/moment/moment/issues/5045
    return value.slice(0, 19);
  }
  return value;
});

/* eslint-disable no-new */
new Vue({
  router,
  store,
  i18n,
  render: h => h(App)
}).$mount("#app");
