<template>
  <div class="row">
    <ConfirmAction
      :show-modal="showModal"
      @confirmed="killAgent"
      @cancel="cancelAction"
      :question="$t('confirm-killing-agent')"
    />
    <ConfirmAction
      :show-modal="showDeleteModal"
      @confirmed="deleteAgent"
      @cancel="cancelAction"
      :question="$t('confirm-remove-agent')"
    />
    <div class="col-12">
      <card :title="$t('sidebar.agents')">
        <ul class="nav nav-tabs">
          <li class="nav-item">
            <span
              style="cursor: pointer"
              class="nav-link btn-link"
              :class="{ active: activeTab === 'list' }"
              @click="activeTab = 'list'"
              >{{ $t("agents.list") }}</span
            >
          </li>
          <li class="nav-item">
            <span
              style="cursor: pointer"
              class="nav-link btn-link"
              :class="{ active: activeTab === 'graph' }"
              @click="activeTab = 'graph'"
              >{{ $t("agents.graph") }}</span
            >
          </li>
        </ul>
        <div class="tab-content">
          <div class="tab-pane" :class="{ active: activeTab === 'list' }">
            <base-table
              class="table-responsive-sm table-responsive-md"
              :data="agents"
              :columns="headers"
              :showActions="true"
              :actions="{ edit: true, delete: true, interact: true }"
              :actionIcons="{
                edit: 'fas fa-trash',
                delete: 'fas fa-skull',
                interact: 'fas fa-terminal'
              }"
              :actionTooltips="{
                edit: $t('tooltip.remove'),
                delete: $t('tooltip.kill'),
                interact: $t('tooltip.interact')
              }"
              @interact="gotoAgentInterface"
              @kill="confirmKillingAgent"
              @edit="confirmDeleatingAgent"
              thead-classes="text-primary"
              :mobileColumns="mobileHeaders"
              style="table-layout:fixed;"
            >
            </base-table>
          </div>
          <div class="tab-pane" :class="{ active: activeTab === 'graph' }">
            <div class="row">
              <div class="col-12">
                <PivotGraph v-if="initialized && activeTab === 'graph'" />
              </div>
            </div>
          </div>
        </div>
      </card>
    </div>
  </div>
</template>
<script>
import { mapState, mapGetters, mapMutations, mapActions } from "vuex";
import PivotGraph from "./Agent/PivotGraph";
import ConfirmAction from "./Modals/ConfirmAction";

export default {
  data() {
    return {
      headers: ["Name", "Key", "OS", "LocalIP", "ExternalIP", "type", "LastCheckin", "IsElevated"],
      mobileHeaders: ["Name", "type"],
      activeTab: "list",
      showModal: false,
      showDeleteModal: false,
      currentItem: null
    };
  },
  components: {
    PivotGraph,
    ConfirmAction
  },
  computed: {
    agents() {
      return this.rowAgents.map(item => {
        // eslint-disable-next-line
        item.type = this.listenerType(item);
        if (item.LastCheckin) {
          // eslint-disable-next-line
          item.LastCheckin = this.$options.filters.datetime(item.LastCheckin);
        }
        return item;
      });
    },
    ...mapState({
      rowAgents: state => state.agents.agents,
      debug: state => state.debug,
      initialized: state => state.agents.initialized
    }),
    ...mapGetters({
      getListenerByKey: "listeners/getListenerByKey"
    })
  },
  methods: {
    gotoAgentInterface(item) {
      const agentUUID = item.Key;
      this.$router.push(`/agents/${agentUUID}`);
    },
    confirmKillingAgent(item) {
      this.currentItem = item;
      this.showModal = true;
    },
    confirmDeleatingAgent(item) {
      this.currentItem = item;
      this.showDeleteModal = true;
    },
    cancelAction() {
      this.currentItem = null;
      this.showModal = false;
      this.showDeleteModal = false;
    },
    killAgent() {
      const data = {
        name: this.currentItem.Key,
        action: "kill",
        options: null
      };
      this.sendJob(data);
      this.currentItem = null;
    },
    deleteAgent() {
      this.removeAgent(this.currentItem.Key);
    },
    listenerType(item) {
      const listener = this.getListenerByKey(item.ListenerKey);
      return typeof listener === "undefined"
        ? `error: listener with UUID="${item.ListenerKey}" not found`
        : listener.LType;
    },
    ...mapActions({
      sendJob: "agents/sendJob",
      removeAgent: "agents/removeAgent"
    }),
    ...mapMutations({
      destroyPivotGraph: "metrics/destroyPivotGraph"
    })
  },
  beforeRouteLeave(to, from, next) {
    this.destroyPivotGraph();
    next();
  }
};
</script>
