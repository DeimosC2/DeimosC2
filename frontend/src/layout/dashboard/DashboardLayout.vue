<template>
  <div class="wrapper">
    <Modals />
    <side-bar>
      <template slot="links">
        <sidebar-link
          to="/dashboard"
          :name="$t('sidebar.dashboard')"
          icon="tim-icons icon-chart-pie-36"
        />
        <sidebar-link to="/listeners" :name="$t('sidebar.listeners')" icon="tim-icons icon-wifi" />
        <sidebar-link to="/agents" :name="$t('sidebar.agents')" icon="tim-icons icon-user-run" />
        <sidebar-link to="/webshells" :name="$t('sidebar.webshells')" icon="tim-icons icon-paper" />
        <sidebar-link to="/loot" :name="$t('sidebar.loot')" icon="tim-icons icon-trophy" />
        <sidebar-link
          to="/end-game"
          :name="$t('sidebar.endGame')"
          icon="tim-icons icon-button-power"
          v-if="isAdmin"
        />
      </template>
    </side-bar>
    <div class="main-panel">
      <top-navbar></top-navbar>

      <dashboard-content @click.native="toggleSidebar"> </dashboard-content>
    </div>
  </div>
</template>
<style lang="scss"></style>
<script>
import { mapState } from "vuex";
import TopNavbar from "./TopNavbar.vue";
import DashboardContent from "./Content.vue";
import Modals from "./Modals";
// import MobileMenu from "./MobileMenu";

export default {
  components: {
    TopNavbar,
    DashboardContent,
    Modals
  },
  computed: {
    ...mapState({
      isAdmin: state => state.auth.isAdmin
    })
  },
  methods: {
    toggleSidebar() {
      if (this.$sidebar.showSidebar) {
        this.$sidebar.displaySidebar(false);
      }
    }
  }
};
</script>

<style lang="scss" scoped>
.main-panel {
  border-top: none;
}
</style>
