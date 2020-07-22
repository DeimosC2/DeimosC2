<template>
  <div>
    <base-alert type="danger"> You are going to delete {{ config.path }} </base-alert>
    <div class="pull-right">
      <base-button type="danger" @click="removeFile">
        {{ $t("buttons.confirm") }}
      </base-button>
    </div>
  </div>
</template>

<script>
import { mapActions } from "vuex";

export default {
  name: "ConfirmRemovingFile",
  props: {
    config: {
      Type: Object,
      required: true
    }
  },
  data() {
    return {
      module: this.config.module,
      credentials: this.config.credentials
    };
  },
  methods: {
    removeFile() {
      this.$store.dispatch(`${this.module}/removeFile`, {
        credentials: this.credentials,
        path: this.config.path
      });
      // refresh files tree
      let path = this.config.path.split("/");
      if (this.config.isPath) {
        path.pop(); // last slash
        path.pop(); // last part of the path that was removed
        path = `${path.join("/")}/`;
      } else {
        path.pop(); // last part of the path that was removed
        path = path.join("/");
      }
      this.$store.dispatch(`${this.module}/fileBrowser`, {
        credentials: this.config.credentials,
        startPoint: path
      });
      this.closeModal();
    },
    ...mapActions({
      closeModal: "closeModal"
    })
  }
};
</script>

<style scoped></style>
