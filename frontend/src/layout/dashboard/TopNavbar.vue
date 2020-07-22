<template>
  <nav
    class="navbar navbar-expand-lg navbar-absolute"
    :class="{ 'bg-white': showMenu, 'navbar-transparent': !showMenu }"
  >
    <div class="container-fluid">
      <div class="navbar-wrapper">
        <div class="navbar-toggle d-inline" :class="{ toggled: $sidebar.showSidebar }">
          <button
            type="button"
            class="navbar-toggler"
            aria-label="Navbar toggle button"
            @click="toggleSidebar"
          >
            <span class="navbar-toggler-bar bar1"></span>
            <span class="navbar-toggler-bar bar2"></span>
            <span class="navbar-toggler-bar bar3"></span>
          </button>
        </div>
        <a class="navbar-brand" href="/dashboard" @click.prevent="$router.push('/dashboard')">
          <span class="font-weight-bold">Deimos </span>
          <span class="font-weight-light">C2</span>
        </a>
      </div>
      <button
        class="navbar-toggler"
        type="button"
        @click="toggleMenu"
        data-toggle="collapse"
        data-target="#navigation"
        aria-controls="navigation-index"
        aria-label="Toggle navigation"
      >
        <span class="navbar-toggler-bar navbar-kebab"></span>
        <span class="navbar-toggler-bar navbar-kebab"></span>
        <span class="navbar-toggler-bar navbar-kebab"></span>
      </button>

      <collapse-transition>
        <div class="collapse navbar-collapse show" v-show="showMenu">
          <ul class="navbar-nav" :class="$rtl.isRTL ? 'mr-auto' : 'ml-auto'" style="display: table">
            <!--            <div class="search-bar input-group" @click="searchModalVisible = true">-->
            <!--              &lt;!&ndash; <input type="text" class="form-control" placeholder="Search...">-->
            <!--              <div class="input-group-addon"><i class="tim-icons icon-zoom-split"></i></div> &ndash;&gt;-->
            <!--              <button-->
            <!--                class="btn btn-link"-->
            <!--                id="search-button"-->
            <!--                data-toggle="modal"-->
            <!--                data-target="#searchModal"-->
            <!--              >-->
            <!--                <i class="tim-icons icon-zoom-split"></i>-->
            <!--              </button>-->
            <!--              &lt;!&ndash; You can choose types of search input &ndash;&gt;-->
            <!--            </div>-->
            <!--            <modal-->
            <!--              :show.sync="searchModalVisible"-->
            <!--              class="modal-search"-->
            <!--              id="searchModal"-->
            <!--              :centered="false"-->
            <!--              :show-close="true"-->
            <!--            >-->
            <!--              <input-->
            <!--                slot="header"-->
            <!--                v-model="searchQuery"-->
            <!--                type="text"-->
            <!--                class="form-control"-->
            <!--                id="inlineFormInputGroup"-->
            <!--                placeholder="SEARCH"-->
            <!--              />-->
            <!--            </modal>-->
            <li class="dropdown nav-item" style="display: table-cell">
              <a
                href="#"
                class="dropdown-toggle nav-link"
                @click.prevent="reconnect()"
                :class="{
                  'text-success': SocketConnected,
                  'text-danger': ReconnectError,
                  'text-default': !SocketConnected && !ReconnectError
                }"
                v-tooltip="getStatus()"
              >
                {{ getStatus() }}
              </a>
            </li>
            <!--            // Comment notifications block as we don't need it now -->
            <!--            <base-dropdown tag="li" :menu-on-right="!$rtl.isRTL" title-tag="a" class="nav-item">-->
            <!--              <a-->
            <!--                slot="title"-->
            <!--                href="#"-->
            <!--                class="dropdown-toggle nav-link"-->
            <!--                data-toggle="dropdown"-->
            <!--                aria-expanded="true"-->
            <!--              >-->
            <!--                <div class="notification d-none d-lg-block d-xl-block"></div>-->
            <!--                <i class="tim-icons icon-sound-wave"></i>-->
            <!--                <p class="d-lg-none">-->
            <!--                  New Notifications-->
            <!--                </p>-->
            <!--              </a>-->
            <!--              <li class="nav-link">-->
            <!--                <a href="#" class="nav-item dropdown-item">You have 5 more tasks</a>-->
            <!--              </li>-->
            <!--              <li class="nav-link">-->
            <!--                <a href="#" class="nav-item dropdown-item">Another one</a>-->
            <!--              </li>-->
            <!--            </base-dropdown>-->
            <base-dropdown
              tag="li"
              :menu-on-right="!$rtl.isRTL"
              title-tag="a"
              class="nav-item"
              menu-classes="dropdown-navbar"
              style="display: table-cell"
            >
              <a slot="title-container" href="#" class="dropdown-toggle nav-link text-danger">
                <img src="/img/login-logo.png" width="30" />
                <b class="caret d-none d-lg-block d-xl-block"></b>
              </a>
              <li class="nav-link">
                <div class="dropdown-item notLink">{{ currentUser }}</div>
              </li>
              <div class="dropdown-divider"></div>
              <li class="nav-link" v-if="isAdmin">
                <router-link class="nav-item dropdown-item" to="/users">{{
                  $t("sidebar.manage_users")
                }}</router-link>
              </li>
              <li class="nav-link" v-if="isAdmin">
                <router-link class="nav-item dropdown-item" to="/admin">{{
                  $t("sidebar.settings")
                }}</router-link>
              </li>
              <li class="nav-link">
                <router-link class="nav-item dropdown-item" to="/preferences">{{
                  $t("sidebar.preferences")
                }}</router-link>
              </li>
              <div class="dropdown-divider"></div>
              <li class="nav-link">
                <a href="#" class="nav-item dropdown-item" @click.prevent="confirmLogout">{{
                  $t("sidebar.logout")
                }}</a>
              </li>
            </base-dropdown>
          </ul>
        </div>
      </collapse-transition>
    </div>
  </nav>
</template>
<script>
import { mapState, mapActions } from "vuex";
import { CollapseTransition } from "vue2-transitions";

export default {
  components: {
    CollapseTransition
  },
  computed: {
    routeName() {
      const { name } = this.$route;
      return this.capitalizeFirstLetter(name);
    },
    isRTL() {
      return this.$rtl.isRTL;
    },
    getEnv() {
      const debugging = process.env.VUE_APP_DEBUG ? this.$t("settings.debug-mode") : "";
      return `${process.env.VUE_APP_ENV} ${debugging}`;
    },
    ...mapState({
      SocketConnected: state => state.socket.SocketConnected,
      ReconnectError: state => state.socket.ReconnectError,
      isAdmin: state => state.auth.isAdmin,
      currentUser: state => state.auth.userName
    })
  },
  data() {
    return {
      activeNotifications: false,
      showMenu: false,
      searchModalVisible: false,
      searchQuery: ""
    };
  },
  methods: {
    capitalizeFirstLetter(string) {
      return string.charAt(0).toUpperCase() + string.slice(1);
    },
    toggleNotificationDropDown() {
      this.activeNotifications = !this.activeNotifications;
    },
    closeDropDown() {
      this.activeNotifications = false;
    },
    toggleSidebar() {
      this.$sidebar.displaySidebar(!this.$sidebar.showSidebar);
    },
    hideSidebar() {
      this.$sidebar.displaySidebar(false);
    },
    toggleMenu() {
      this.showMenu = !this.showMenu;
    },
    getStatus() {
      if (this.SocketConnected) return this.$t("settings.status-connected");
      return this.ReconnectError
        ? this.$t("settings.status-offline")
        : this.$t("settings.status-connecting");
    },
    reconnect() {
      if (!this.SocketConnected) {
        this.SOCKET_CONNECT();
      }
    },
    confirmLogout() {
      this.openModal({ type: "confirmLogout", data: {} });
    },
    ...mapActions({
      SOCKET_CONNECT: "SOCKET_CONNECT",
      openModal: "openModal"
    })
  }
};
</script>
<style></style>
