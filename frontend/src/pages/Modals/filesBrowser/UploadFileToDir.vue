<template>
  <div>
    <div class="row">
      <div class="col-lg-12">
        {{ config.path }}
      </div>
    </div>
    <div class="row">
      <div class="col-lg-12">
        <FileSelector @selected="attachFile($event)" :showUploadButton="false" />
      </div>
    </div>

    <div class="row">
      <div class="col-lg-12">
        <base-button
          type="primary"
          class="pull-right"
          :disabled="saving || !socketConnected"
          @click="upload()"
          :loading="saving"
        >
          {{ $t("buttons.send") }}
        </base-button>
      </div>
    </div>
  </div>
</template>

<script>
import { mapActions, mapState } from "vuex";
import FileSelector from "../../../components/FileSelector";

export default {
  name: "UploadFileToDir",
  props: {
    config: {
      Type: Object,
      required: true
    }
  },
  components: {
    FileSelector
  },
  data() {
    return {
      module: this.config.module,
      credentials: this.config.credentials,
      files: []
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
        this.$store.dispatch(`${this.module}/fileBrowser`, {
          credentials: this.credentials,
          startPoint: this.config.path
        });
      }
    }
  },
  methods: {
    upload() {
      this.$store.commit(`${this.module}/startSavingFile`);
      this.$store.dispatch(`${this.module}/fileUpload`, {
        credentials: this.credentials,
        path: this.config.path,
        files: this.files
      });
    },
    attachFile(file) {
      const newFiles = [];
      file.forEach(item => {
        const reader = new FileReader();
        reader.onloadend = () => {
          const b64 = reader.result.replace(/^data:.+;base64,/, "");
          newFiles.push({ name: item.name, b64 });
        };
        reader.readAsDataURL(item);
      });
      this.files = newFiles;
    },
    ...mapActions({
      closeModal: "closeModal"
    })
  }
};
</script>

<style scoped></style>
