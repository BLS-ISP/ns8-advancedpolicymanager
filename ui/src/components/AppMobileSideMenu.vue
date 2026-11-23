<template>
  <cv-side-nav
    id="side-nav"
    fixed
    expanded
    v-if="isAppSideMenuShown"
    class="app-mobile-side-menu"
  >
    <AppSideMenuContent @closeSideMenu="closeSideMenu" />
  </cv-side-nav>
</template>

<script>
import AppSideMenuContent from "./AppSideMenuContent.vue";
import { mapState, mapActions } from "vuex";

export default {
  name: "AppMobileSideMenu",
  components: {
    AppSideMenuContent,
  },
  computed: {
    ...mapState(["isAppSideMenuShown"]),
  },
  methods: {
    ...mapActions(["setAppSideMenuShownInStore"]),
    closeSideMenu() {
      this.setAppSideMenuShownInStore(false);
    },
  },
};
</script>
