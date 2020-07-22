<template>
  <div>
    <div class="row">
      <div class="col-md-12">
        <BackupSettings v-if="initialized" />
      </div>
    </div>
    <div class="row">
      <div class="col-md-12">
        <EnvironmentSettings />
      </div>
    </div>
    <div class="row">
      <div class="col-md-12">
        <WebSocketApiTester />
      </div>
    </div>
  </div>
</template>
<script>
import { mapState } from "vuex";
import EnvironmentSettings from "./Admin/EnvironmentSettings";
import WebSocketApiTester from "./Admin/WebSocketApiTester";
import BackupSettings from "./Admin/BackupSettings";

export default {
  components: {
    EnvironmentSettings,
    WebSocketApiTester,
    BackupSettings
  },
  computed: {
    ...mapState({
      initialized: state => state.agents.initialized
    })
  }
};
</script>
<style></style>
