<template>
  <div class="app-side-menu-content">
    <div class="instance-name">
      <div v-if="instanceLabel">{{ instanceLabel }}</div>
      <div v-else-if="instanceName">{{ instanceName }}</div>
      <cv-skeleton-text v-else :heading="true" width="80%" />
    </div>

    <cv-side-nav-items>
      <cv-side-nav-link
        @click="goToAppPage('/status')"
        :active="isLinkActive('/status')"
      >
        <template v-slot:nav-icon>
          <Activity20 />
        </template>
        <span>{{ $t("status.title") }}</span>
      </cv-side-nav-link>

      <cv-side-nav-link
        @click="goToAppPage('/settings')"
        :active="isLinkActive('/settings')"
      >
        <template v-slot:nav-icon>
          <Settings20 />
        </template>
        <span>{{ $t("settings.title") }}</span>
      </cv-side-nav-link>

      <cv-side-nav-link
        @click="goToAppPage('/about')"
        :active="isLinkActive('/about')"
      >
        <template v-slot:nav-icon>
          <Information20 />
        </template>
        <span>{{ $t("about.title") }}</span>
      </cv-side-nav-link>
    </cv-side-nav-items>
  </div>
</template>

<script>
import Activity20 from "@carbon/icons-vue/es/activity/20";
import Settings20 from "@carbon/icons-vue/es/settings/20";
import Information20 from "@carbon/icons-vue/es/information/20";
import { mapState } from "vuex";

export default {
  name: "AppSideMenuContent",
  components: {
    Activity20,
    Settings20,
    Information20,
  },
  computed: {
    ...mapState(["instanceName", "instanceLabel"]),
  },
  methods: {
    isLinkActive(path) {
      return this.$route.path === path;
    },
    goToAppPage(path) {
      if (this.$route.path !== path) {
        this.$router.push(path);
      }
      this.$emit("closeSideMenu");
    },
  },
};
</script>

<style scoped>
.instance-name {
  padding: 1rem 1rem 0.75rem;
  font-weight: 600;
  font-size: 0.95rem;
  border-bottom: 1px solid #e0e0e0;
  margin-bottom: 0.5rem;
}
</style>
