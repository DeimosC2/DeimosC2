<template>
  <div>
    <!--    <h5>Download generated scripts:</h5>-->
    <!--    <ul>-->
    <!--      <li v-for="item in generatedShells" :key="item.file">-->
    <!--        <a :href="item.file" target="_blank">{{ item.name }}</a>-->
    <!--      </li>-->
    <!--    </ul>-->
    <!--    <h5>Or generate new one</h5>-->
    <base-alert type="danger" v-if="saveError">{{ saveError }}</base-alert>
    <select class="type-dropdown" v-model="type">
      <option :value="null" disabled selected>{{ $t("table.type") }}</option>
      <option v-for="item in types" :value="item" :key="item">{{ item }}</option>
    </select>
    <div class="pull-right">
      <base-button
        :loading="saving"
        type="primary"
        :disabled="!type || saving"
        @click="generateWebShell"
      >
        {{ $t("buttons.generate") }}
      </base-button>
    </div>
  </div>
</template>

<script>
import { mapActions, mapMutations, mapState } from "vuex";

export default {
  name: "GenerateWebShell",
  data() {
    return {
      type: null
    };
  },
  computed: {
    ...mapState({
      types: state => state.webShells.types,
      generatedShells: state => state.webShells.generatedShells,
      saving: state => state.webShells.saving,
      saveError: state => state.webShells.saveError
    })
  },
  watch: {
    saving(newValue, oldValue) {
      if (oldValue && !newValue && !this.saveError) {
        this.closeModal();
      }
    }
  },
  methods: {
    generateWebShell() {
      this.startGenerating(true);
      this.generateWebShellCommand(this.type);
    },
    ...mapActions({
      generateWebShellCommand: "webShells/generateWebShell",
      fetchGeneratedWebShells: "webShells/fetchGeneratedWebShells",
      closeModal: "closeModal"
    }),
    ...mapMutations({
      startGenerating: "webShells/saving",
      clearSaver: "webShells/clearSaver"
    })
  },
  mounted() {
    this.fetchGeneratedWebShells();
  },
  beforeDestroy() {
    this.clearSaver();
  }
};
</script>
