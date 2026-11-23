<template>
  <div id="ns8-app">
    <cv-content id="main-content" class="app-main-content">
      <AppSideMenuContent class="desktop-side-menu" />
      <AppMobileSideMenu />
      <div class="app-view-container">
        <router-view />
      </div>
    </cv-content>
  </div>
</template>

<script>
import AppSideMenuContent from "./components/AppSideMenuContent.vue";
import AppMobileSideMenu from "./components/AppMobileSideMenu.vue";
import {
  QueryParamService,
  TaskService,
  UtilService,
} from "@nethserver/ns8-ui-lib";
import { mapState, mapActions } from "vuex";
import to from "./utils/to";

export default {
  name: "App",
  components: {
    AppSideMenuContent,
    AppMobileSideMenu,
  },
  mixins: [QueryParamService, TaskService, UtilService],
  computed: {
    ...mapState(["instanceName", "core"]),
  },
  created() {
    const core = window.parent && window.parent.core ? window.parent.core : null;
    this.setCoreInStore(core);

    const hashMatch = window.parent
      ? /#\/apps\/([a-zA-Z0-9_-]+)/.exec(window.parent.location.hash)
      : null;
    const detectedInstance = hashMatch ? hashMatch[1] : "advancedpolicymanager1";
    this.setInstanceNameInStore(detectedInstance);

    if (core && core.$root) {
      core.$root.$on("changeLocale", (lang) => {
        if (lang && this.$i18n) {
          this.$i18n.locale = lang;
        }
      });
      core.$root.$on("toggleMobileSideMenu", () => {
        this.setAppSideMenuShownInStore(!this.$store.state.isAppSideMenuShown);
      });
      this.listenToClusterEvents(core);
      this.retrieveInstalledModules();
    }
  },
  methods: {
    ...mapActions([
      "setInstanceNameInStore",
      "setInstanceLabelInStore",
      "setCoreInStore",
      "setAppSideMenuShownInStore",
    ]),
    listenToClusterEvents(core) {
      core.$root.$on(
        `${this.instanceName}-task-completed`,
        this.onModuleTaskCompleted
      );
    },
    onModuleTaskCompleted() {
      this.retrieveInstalledModules();
    },
    async retrieveInstalledModules() {
      const taskAction = "list-installed-modules";
      const eventId = this.getUuid();

      if (!this.core || !this.core.$root) {
        return;
      }

      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        this.listInstalledModulesCompleted
      );

      const [err] = await to(
        this.createClusterTaskForApp({
          action: taskAction,
          extra: {
            title: this.$t("action." + taskAction),
            isNotificationHidden: true,
            eventId,
          },
        })
      );

      if (err) {
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task", { action: taskAction })
        );
      }
    },
    listInstalledModulesCompleted(taskContext, taskResult) {
      const modules = [];
      if (taskResult && taskResult.output) {
        for (const instanceList of Object.values(taskResult.output)) {
          if (Array.isArray(instanceList)) {
            modules.push(...instanceList);
          }
        }
      }
      const current = modules.find((m) => m.id === this.instanceName);
      if (current && current.ui_name) {
        this.setInstanceLabelInStore(current.ui_name);
      }
    },
  },
};
</script>

<style scoped>
.app-main-content {
  display: flex;
  min-height: 100vh;
  background: #f4f4f4;
  padding: 0;
}

.desktop-side-menu {
  width: 16rem;
  background: #ffffff;
  border-right: 1px solid #e0e0e0;
  flex-shrink: 0;
}

.app-view-container {
  flex: 1;
  padding: 2rem;
  max-width: 100%;
  overflow-x: hidden;
}

@media (max-width: 66rem) {
  .desktop-side-menu {
    display: none;
  }
  .app-view-container {
    padding: 1rem;
  }
}
</style>
