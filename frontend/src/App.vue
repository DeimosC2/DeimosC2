<template>
  <div>
    <notifications></notifications>
    <ThanosSnapEffect
      @ready="readyToDust(true)"
      @error="logError"
      :startAnimation="startAnimation"
      :page-ready="pageReady"
    >
      <router-view :key="$route.fullPath"></router-view>
    </ThanosSnapEffect>
  </div>
</template>

<script>
import { mapState, mapMutations } from "vuex";
import ThanosSnapEffect from "vue-thanos-snap-effect";

export default {
  components: {
    ThanosSnapEffect
  },
  computed: {
    ...mapState({
      mustChangePassword: state => state.auth.mustChangePassword,
      mustEnterMFA: state => state.auth.mustEnterMFA,
      pageReady: state => state.dust.pageReady,
      startAnimation: state => state.dust.start
    })
  },
  watch: {
    mustChangePassword(newValue) {
      if (newValue) {
        this.$router.push("/password-change");
      }
    },
    mustEnterMFA(newValue) {
      if (newValue) {
        this.$router.push("/mfa");
      }
    }
  },
  methods: {
    disableRTL() {
      if (!this.$rtl.isRTL) {
        this.$rtl.disableRTL();
      }
    },
    toggleNavOpen() {
      const root = document.getElementsByTagName("html")[0];
      root.classList.toggle("nav-open");
    },
    logError(err) {
      console.log("Thanos error", err);
    },
    readyToDust() {
      this.doReadyToDust(true);
    },
    ...mapMutations({
      doReadyToDust: "readyToDust"
    })
  },
  mounted() {
    this.$watch("$route", this.disableRTL, { immediate: true });
    this.$watch("$sidebar.showSidebar", this.toggleNavOpen);
  }
};
</script>
