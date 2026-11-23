import "carbon-components/css/carbon-components.min.css";
import "./styles/_base.css";

import Vue from "vue";
import CarbonComponentsVue from "@carbon/vue";
import VueI18n from "vue-i18n";
import VueDateFns from "vue-date-fns";
import axios from "axios";
import Ns8UiLib, { Filters } from "@nethserver/ns8-ui-lib";

import App from "./App.vue";
import router from "./router";
import store from "./store";

import enMessages from "../public/i18n/en/translation.json";
import deMessages from "../public/i18n/de/translation.json";

Vue.config.productionTip = false;
Vue.use(CarbonComponentsVue);
Vue.use(VueI18n);
Vue.use(VueDateFns);
Vue.use(Ns8UiLib);

Vue.prototype.axios = axios;

Object.keys(Filters).forEach((filterName) => {
  Vue.filter(filterName, Filters[filterName]);
});

function detectInitialLocale() {
  try {
    if (
      window.parent &&
      window.parent.core &&
      window.parent.core.$i18n &&
      window.parent.core.$i18n.locale
    ) {
      const parentLang = String(window.parent.core.$i18n.locale).split("-")[0];
      if (parentLang === "de" || parentLang === "en") {
        return parentLang;
      }
    }
  } catch (_) {
    // Ignore cross-frame access issues in standalone mode
  }
  const navLang = (navigator.language || "en").split("-")[0].toLowerCase();
  return navLang === "de" ? "de" : "en";
}

const i18n = new VueI18n({
  locale: detectInitialLocale(),
  fallbackLocale: "en",
  silentFallbackWarn: true,
  messages: {
    en: enMessages,
    de: deMessages,
  },
});

new Vue({
  router,
  store,
  i18n,
  render: (h) => h(App),
}).$mount("#app");
