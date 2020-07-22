<template>
  <div class="row">
    <div class="col-lg-12">
      <Term
        :agent="agent"
        module="webshell"
        :commands="commands"
        v-if="shell"
        :showSwitches="false"
      />
    </div>
  </div>
</template>

<script>
import WebshellCommands from "@C2/plugins/jquery-terminal/webshellCommands";
import { mapGetters } from "vuex";
import Term from "../components/Term";

export default {
  name: "WebShellsInterface",
  components: {
    Term
  },
  data() {
    return {
      shell: null
    };
  },
  computed: {
    agent() {
      return {
        Name: this.shell.UUID,
        Username: this.shell.Username,
        Hostname: this.shell.Hostname,
        OS: this.shell.OS,
        Shellz: ["cmd", "power"]
      };
    },
    commands() {
      return new WebshellCommands(this.agent.Key);
    },
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
