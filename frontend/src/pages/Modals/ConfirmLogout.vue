<template>
  <div class="row">
    <div class="col-6">
      <base-button type="danger" @click="closeModal">{{ $t("buttons.cancel") }}</base-button>
    </div>
    <div class="col-6">
      <base-button
        type="success"
        class="pull-right"
        @click="logout()"
        :loading="processingLogout"
        >{{ $t("buttons.confirm") }}</base-button
      >
    </div>
  </div>
</template>

<script>
import { mapActions } from "vuex";

export default {
  name: "ConfirmLogout",
  data() {
    return {
      processingLogout: false
    };
  },
  methods: {
    logout() {
      this.$logging("Logout::logout function", this.debug);
      this.processingLogout = true;
      this.$axios.get("/log.out").then(() => {
        this.processingLogout = false;
        this.closeModal();
        window.location.href = "/login";
      });
    },
    ...mapActions({
      closeModal: "closeModal"
    })
  }
};
</script>

<style scoped></style>
