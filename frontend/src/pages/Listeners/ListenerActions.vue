<template>
  <div class="row">
    <div class="col-lg-12">
      <card type="task" :title="$t('listeners.actions')">
        <base-button type="primary" style="width: 100%" @click="downloadKey()">
          {{ $t("listeners.privateKey") }}
        </base-button>
      </card>
    </div>
    <div class="col-lg-12">
      <card type="task" :title="$t('agents.agents')">
        <div class="row" v-for="item in generatedAgents" :key="item">
          <div class="col-lg-12">
            <a :href="`/${item}`" class="text-white" target="_blank">
              {{ item.replace(`listenerresources/${listener.Key}/`, "") }}
            </a>
          </div>
        </div>
        <base-button type="success" style="width: 100%" @click="generateAgent()" class="mt-3">
          {{ $t("agents.generate_agent") }}
        </base-button>
      </card>
    </div>
  </div>
</template>

<script>
import { mapActions, mapState } from "vuex";

export default {
  props: {
    listener: Object
  },
  data() {
    return {};
  },
  computed: {
    ...mapState({
      generatedAgents: state => state.listeners.agents
    })
  },
  methods: {
    downloadKey() {
      this.getListenerPrivateKey(this.listener);
    },
    generateAgent() {
      this.openModal({ type: "generateAgent", data: this.listener });
    },
    ...mapActions({
      getListenerPrivateKey: "listeners/getListenerPrivateKey",
      getCompiledAgents: "listeners/getCompiledAgents",
      openModal: "openModal"
    })
  },
  mounted() {
    this.getCompiledAgents(this.listener.Key);
  }
};
</script>
