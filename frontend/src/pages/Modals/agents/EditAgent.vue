<template>
  <div>
    <base-input type="text" :label="$t('agents.name')" v-model="agent['Name']"> </base-input>

    <div class="pull-right">
      <base-button type="primary" @click="updateAgent()">
        {{ $t("buttons.update") }}
      </base-button>
    </div>
  </div>
</template>

<script>
import { mapActions } from "vuex";

export default {
  name: "EditUser",
  props: {
    agent: {
      Type: Object,
      required: true
    }
  },
  methods: {
    updateAgent() {
      this.setName(this.agent);
      this.closeModal();
    },
    ...mapActions({
      closeModal: "closeModal",
      setName: "agents/setName"
    })
  }
};
</script>
