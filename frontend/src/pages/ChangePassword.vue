<template>
  <div class="row">
    <card type="login" style="width: 20rem;" class="col-lg-4 offset-lg-3">
      <img slot="image" class="card-img-top" src="/img/login-logo.png" alt="DeimosC2 Logo" />
      <h4 class="card-title">Change Password to continue</h4>
      <slot>
        <base-alert type="danger" v-if="saveError">{{ saveError }}</base-alert>
        <base-input type="password" label="Old password" v-model="OldPass"> </base-input>
        <base-input type="password" label="New password" v-model="NewPass"> </base-input>
      </slot>
      <slot name="footer">
        <base-button :loading="saving" type="primary" :disabled="saving" @click="updatePassword()">
          Continue
        </base-button>
      </slot>
    </card>
  </div>
</template>
<script>
import { mapActions, mapMutations, mapState } from "vuex";
import store from "../store";

export default {
  beforeRouteEnter(to, from, next) {
    if (!store.state.auth.mustChangePassword) {
      next("/");
    } else {
      next();
    }
  },
  name: "ChangePassword",
  data() {
    return {
      OldPass: null,
      NewPass: null
    };
  },
  computed: {
    ...mapState({
      saving: state => state.admin.saving,
      saveError: state => state.admin.saveError
    })
  },
  methods: {
    updatePassword() {
      if (this.OldPass && this.NewPass && this.OldPass !== this.NewPass) {
        this.clearSaver();
        this.startSaving(true);
        this.editPassword({ OldPass: this.OldPass, NewPass: this.NewPass });
      } else {
        this.setSaveError("The new password cannot be blank or the same as the old one");
      }
    },
    ...mapActions({
      editPassword: "admin/editPassword"
    }),
    ...mapMutations({
      clearSaver: "admin/clearSaver",
      setSaveError: "admin/saveError",
      startSaving: "admin/saving"
    })
  }
};
</script>
