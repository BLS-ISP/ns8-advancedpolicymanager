import Vue from "vue";
import Vuex from "vuex";

Vue.use(Vuex);

export default new Vuex.Store({
  state: {
    instanceName: "",
    instanceLabel: "",
    core: null,
    appName: "advancedpolicymanager",
    isAppSideMenuShown: false,
  },
  getters: {
    instanceName: (state) => state.instanceName,
    instanceLabel: (state) => state.instanceLabel,
    core: (state) => state.core,
  },
  mutations: {
    setInstanceName(state, instanceName) {
      state.instanceName = instanceName;
    },
    setInstanceLabel(state, instanceLabel) {
      state.instanceLabel = instanceLabel;
    },
    setCoreInStore(state, core) {
      state.core = core;
    },
    setAppSideMenuShownInStore(state, value) {
      state.isAppSideMenuShown = value;
    },
  },
  actions: {
    setInstanceNameInStore({ commit }, instanceName) {
      commit("setInstanceName", instanceName);
    },
    setInstanceLabelInStore({ commit }, instanceLabel) {
      commit("setInstanceLabel", instanceLabel);
    },
    setCoreInStore({ commit }, core) {
      commit("setCoreInStore", core);
    },
    setAppSideMenuShownInStore({ commit }, value) {
      commit("setAppSideMenuShownInStore", value);
    },
  },
});
