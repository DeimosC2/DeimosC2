<template>
  <div>
    <div class="row">
      <div class="col-lg-10">
        <div class="pull-right">
          {{ config.path }}
        </div>
      </div>
      <div class="col-lg-2">
        <base-input v-model="dirName" @keyup.enter.native="makeDir()" />
      </div>
    </div>
    <div class="row">
      <div class="col-lg-12">
        <base-button
          type="primary"
          class="pull-right"
          :disabled="saving || !socketConnected"
          @click="makeDir()"
          :loading="saving"
        >
          {{ $t("buttons.create") }}
        </base-button>
      </div>
    </div>
  </div>
</template>

<script>
import { mapActions, mapState } from "vuex";

export default {
  name: "MakeDir",
  props: {
    config: {
      Type: Object,
      required: true
    }
  },
  data() {
    return {
      module: this.config.module,
      credentials: this.config.credentials,
      dirName: null
    };
  },
  computed: {
    ...mapState({
      saving(state) {
        return state[this.module].fileSaving;
      },
      socketConnected: state => state.socket.SocketConnected
    })
  },
  watch: {
    saving(newValue, oldValue) {
      if (oldValue && !newValue) {
        this.closeModal();
        // refresh files tree
        this.$store.dispatch(`${this.module}/fileBrowser`, {
          credentials: this.config.credentials,
          startPoint: this.config.path
        });
      }
    }
  },
  methods: {
    makeDir() {
      this.$store.commit(`${this.module}/startSavingFile`);
      this.$store.dispatch(`${this.module}/makeDir`, {
        credentials: this.credentials,
        path: this.config.path + this.dirName
      });
    },
    ...mapActions({
      closeModal: "closeModal"
    })
  }
};
</script>

<style scoped></style>
