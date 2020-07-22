<template>
  <div>
    {{ editingFilePath }}
    <span v-if="fetching" class="fas fa-sync-alt fa-spin mr-2"></span>
    <template v-if="!fetching">
      <codemirror v-model="editText" :options="cmOptions" @keyup.esc.native="closeModal" />
    </template>

    <div class="row">
      <div class="col-lg-12">
        <base-button
          type="primary"
          class="pull-right"
          :disabled="saving || !socketConnected"
          @click="saveFile()"
          :loading="saving"
        >
          {{ $t("buttons.save") }}
        </base-button>
        <div v-if="fileSaveResult">{{ fileSaveResult }}</div>
      </div>
    </div>
  </div>
</template>

<script>
import { mapActions, mapState } from "vuex";

export default {
  name: "EditFile",
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
      editText: null,
      cmOptions: {
        theme: "base16-dark",
        lineNumbers: true,
        line: true,
        mode: "application/x-aspx"
      }
    };
  },
  computed: {
    ...mapState({
      editingFilePath(state) {
        return state[this.module].editingFilePath;
      },
      editingFileContent(state) {
        return state[this.module].editingFileContent;
      },
      fetching(state) {
        return state[this.module].fileFetching;
      },
      saving(state) {
        return state[this.module].fileSaving;
      },
      fileSaveResult(state) {
        return state[this.module].fileSaveResult;
      },
      socketConnected: state => state.socket.SocketConnected
    })
  },
  watch: {
    editingFileContent() {
      this.editText = this.editingFileContent;
    }
  },
  methods: {
    saveFile() {
      this.$store.commit(`${this.module}/startSavingFile`);
      this.$store.dispatch(`${this.module}/writeFile`, {
        credentials: this.credentials,
        path: this.editingFilePath,
        content: this.editText
      });
    },
    ...mapActions({
      closeModal: "closeModal"
    })
  }
};
</script>

<style scoped></style>
