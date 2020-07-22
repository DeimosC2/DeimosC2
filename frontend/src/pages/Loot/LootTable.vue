<template>
  <div>
    <base-table
      :data="loot"
      :columns="headers"
      :showActions="false"
      thead-classes="text-primary"
      :mobileColumns="mobileHeaders"
      class="table-responsive-sm"
      style="table-layout:fixed;"
    >
    </base-table>
  </div>
</template>

<script>
import { mapActions, mapState } from "vuex";

export default {
  name: "LootTable",
  props: {
    agentKey: {
      default: null
    }
  },
  data() {
    return {
      headers: ["username", "password", "hash", "credType", "isWebshell", "host", "domain"],
      mobileHeaders: ["username", "credType", "isWebshell"]
    };
  },
  computed: {
    ...mapState({
      loot: state => state.loot.loot
    })
  },
  methods: {
    ...mapActions({
      listAgentLoot: "loot/listAgentLoot",
      listLoots: "loot/listLoots"
    })
  },
  mounted() {
    if (!this.agentKey) {
      this.listLoots();
    } else {
      this.listAgentLoot(this.agentKey);
    }
  }
};
</script>

<style scoped></style>
