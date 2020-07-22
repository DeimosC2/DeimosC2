<template>
  <div>
    <card type="task">
      <FileBrowser
        v-if="shell && shell.UUID"
        module="webShells"
        :credentials="shell.UUID"
        startPoint="./"
        :uuid="shell.UUID"
      />
    </card>
  </div>
</template>

<script>
import { mapGetters, mapState } from "vuex";
import FileBrowser from "../components/FileBrowser";

export default {
  name: "WebShellsFiles",
  data() {
    return {
      shell: null
    };
  },
  components: { FileBrowser },
  computed: {
    ...mapState({
      socketConnected: state => state.socket.SocketConnected
    }),
    ...mapGetters({
      getWebShellByUUID: "webShells/getWebShellByUUID"
    })
  },

  mounted() {
    const shellID = this.$route.params.shellUUID;
    this.shell = this.getWebShellByUUID(shellID);
  }
};
</script>

<style scoped></style>
