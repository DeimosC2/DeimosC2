<template>
  <div class="row">
    <div class="col-lg-12">
      {{ $t("users.confirm_delete") }} <b>{{ user.username }}</b
      >?
    </div>
    <div class="col-lg-12">
      <base-button type="primary" class="pull-right" @click="deleteUser">{{
        $t("buttons.confirm")
      }}</base-button>
    </div>
  </div>
</template>

<script>
import { mapActions } from "vuex";

export default {
  name: "DeleteUser",
  props: {
    user: {
      Type: Object,
      required: true
    }
  },
  methods: {
    deleteUser() {
      this.doDeleteUser(this.user.id);
      this.closeModal();
    },
    ...mapActions({
      closeModal: "closeModal",
      doDeleteUser: "admin/deleteUser"
    })
  }
};
</script>

<style scoped></style>
