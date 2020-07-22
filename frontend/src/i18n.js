import Vue from "vue";
import VueI18n from "vue-i18n";
import VueLocalStorage from "vue-localstorage";

Vue.use(VueLocalStorage);

Vue.use(VueI18n);

function loadLocaleMessages() {
  const locales = require.context("./locales", true, /[A-Za-z0-9-_,\s]+\.json$/i);
  const messages = {};
  locales.keys().forEach(key => {
    const matched = key.match(/([a-z0-9]+)\./i);
    if (matched && matched.length > 1) {
      const locale = matched[1];
      messages[locale] = locales(key);
    }
  });
  return messages;
}

const $i18n = new VueI18n({
  locale: process.env.VUE_APP_I18N_LOCALE || "en",
  fallbackLocale: process.env.VUE_APP_I18N_FALLBACK_LOCALE || "en",
  messages: loadLocaleMessages()
});

if (Vue.localStorage.get("lang") === null) {
  Vue.localStorage.set("lang", "en"); // set default theme
  $i18n.locale = "en";
} else {
  $i18n.locale = Vue.localStorage.get("lang");
}
export default $i18n;
