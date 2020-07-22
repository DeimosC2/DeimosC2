<template>
  <div class="wrapper">
    <div class="main-panel">
      <dashboard-content> </dashboard-content>

      <content-footer></content-footer>
    </div>
  </div>
</template>
<style lang="scss"></style>
<script>
import ContentFooter from "./LoginPageFooter.vue";
import DashboardContent from "./Content.vue";

export default {
  components: {
    ContentFooter,
    DashboardContent
  }
};
</script>
