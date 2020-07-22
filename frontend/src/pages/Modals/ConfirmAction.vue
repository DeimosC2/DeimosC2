<template>
  <modal
    :show="showModal"
    :centered="false"
    :show-close="true"
    @keyup.esc.native="closeModal"
    @close="closeModal"
    modalClasses="base-modal"
  >
    <span slot="header">{{ question }}</span>
    <div class="row">
      <div class="col-6">
        <base-button type="danger" @click="closeModal">{{ $t("buttons.cancel") }}</base-button>
      </div>
      <div class="col-6">
        <base-button type="success" class="pull-right" @click="confirm()">{{
          $t("buttons.confirm")
        }}</base-button>
      </div>
    </div>
  </modal>
</template>

<script>
import Modal from "../../components/Modal";

export default {
  name: "ConfirmAction",
  props: {
    showModal: {
      type: Boolean,
      default: false
    },
    question: {
      type: String,
      default: "Are you sure?"
    }
  },
  components: {
    Modal
  },
  methods: {
    confirm() {
      this.$emit("confirmed");
      this.closeModal();
    },
    closeModal() {
      this.$emit("cancel");
    }
  }
};
</script>

<style scoped></style>
