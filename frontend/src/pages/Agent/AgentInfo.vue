<template>
  <card type="task" :title="$t('agents.info-title')">
    <info-table
      style="table-layout:fixed;"
      :data="prettyAgent"
      :columns="columns"
      :editableColumns="['Name']"
      @edit="editAgent()"
    >
    </info-table>
  </card>
</template>
<script>
import { mapActions, mapState } from "vuex";
import _ from "lodash";

export default {
  props: {
    agent: {
      type: Object,
      required: true
    }
  },
  data() {
    return {
      columns: [
        "Key",
        "Name",
        "OS",
        "Hostname",
        "Username",
        "LocalIP",
        "ExternalIP",
        "AgentPath",
        "IsElevated"
      ]
    };
  },
  computed: {
    ...mapState({
      debug: "debug"
    }),
    prettyAgent() {
      const prettyAgent = _.clone(this.agent);
      prettyAgent.OS = `${this.agent.OS} (${this.agent.Pid})`;
      return prettyAgent;
    }
  },
  methods: {
    editAgent() {
      this.openModal({ type: "editAgent", data: this.agent });
    },
    ...mapActions({
      openModal: "openModal"
    })
  }
};
</script>

<style scoped></style>
