<template>
  <div>
    <div class="row">
      <div class="col-lg-6 col-sm-12">
        <card type="chart" :title="$t('dashboard.agentsByOS')" style="height: 95%">
          <div class="chart-area">
            <span class="fas fa-sync-alt fa-spin fa-2x" v-if="!initialized"></span>
            <AgentsByOS v-if="initialized" />
          </div>
        </card>
      </div>
      <div class="col-lg-6 col-sm-12">
        <card type="chart" :title="$t('dashboard.agentsByListener')" style="height: 95%">
          <div class="chart-area">
            <span class="fas fa-sync-alt fa-spin fa-2x" v-if="!initialized"></span>
            <AgentsByListener v-if="initialized" />
          </div>
        </card>
      </div>
    </div>
    <div class="row">
      <div class="col-12">
        <card type="chart" :title="$t('dashboard.totalAgents')">
          <div class="chart-area">
            <span class="fas fa-sync-alt fa-spin fa-2x" v-if="!initialized"></span>
            <AgentsOverTime v-if="initialized" />
          </div>
        </card>
      </div>
    </div>
  </div>
</template>
<script>
import { mapState } from "vuex";
import AgentsByOS from "./Dashboard/AgentsByOS";
import AgentsByListener from "./Dashboard/AgentsByListener";
import AgentsOverTime from "./Dashboard/AgentsOverTime";

export default {
  components: {
    AgentsByOS,
    AgentsByListener,
    AgentsOverTime
  },
  computed: {
    ...mapState({
      initialized: state => state.agents.initialized
    })
  }
};
</script>
<style></style>
