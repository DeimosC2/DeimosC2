<template>
  <div>
    <base-alert type="danger" v-if="saveError">{{ saveError }}</base-alert>
    <form ref="form">
      <div class="row">
        <div class="col-lg-4">
          <select v-model="OS" required class="type-dropdown" @change="validate">
            <option :value="null" disabled selected>OS</option>
            <option v-for="item in OSTypes" :value="item" :key="item">{{ item }}</option>
          </select>
        </div>
        <div class="col-lg-4">
          <select v-model="Arch" required class="type-dropdown" @change="validate">
            <option :value="null" disabled selected>{{ $t("agents.architecture") }}</option>
            <option v-for="item in ArchTypes" :value="item" :key="item">{{ item }}</option>
          </select>
        </div>
        <div class="col-lg-4">
          {{ $t("agents.obfuscated") }}
          <toggle-button v-model="Obfuscate" class="mr-2" :sync="true" />
        </div>
      </div>

      <div class="pull-right">
        <base-button type="primary" :disabled="invalid" @click="generateAgent()" class="mt-3">
          {{ $t("buttons.generate") }}
        </base-button>
      </div>
    </form>
  </div>
</template>

<script>
import { mapState, mapActions, mapMutations } from "vuex";

export default {
  props: {
    listener: {
      required: true,
      type: Object
    }
  },
  data() {
    return {
      OS: null,
      OSTypes: ["windows", "darwin", "linux"],
      Arch: null,
      ArchTypes: ["amd64", "386"],
      Obfuscate: true,
      invalid: true
    };
  },
  computed: {
    ...mapState({
      saveError: state => state.listeners.saveError
    })
  },
  methods: {
    validate() {
      this.invalid = !this.OS || !this.Arch;
    },
    generateAgent() {
      if (!this.invalid) {
        this.clearSaver();
        this.createAgent({
          Key: this.listener.Key,
          Obfuscate: this.Obfuscate,
          Arch: [this.Arch],
          OS: [this.OS]
        });
        this.closeModal();
      }
    },
    ...mapActions({
      createAgent: "listeners/createAgent",
      closeModal: "closeModal"
    }),
    ...mapMutations({
      clearSaver: "listeners/clearSaver"
    })
  },
  beforeDestroy() {
    this.clearSaver();
  }
};
</script>
