<template>
  <div>
    <base-alert type="danger" v-if="saveError">{{ saveError }}</base-alert>
    <base-input type="password" :label="$t('users.old-password')" v-model="OldPass"> </base-input>
    <base-input type="password" label="$t('users.new-password')" v-model="NewPass"> </base-input>

    <div class="pull-right">
      <base-button :loading="saving" type="primary" :disabled="saving" @click="updatePassword()">
        {{ $t("buttons.continue") }}
      </base-button>
    </div>
  </div>
</template>

<script>
import { mapActions, mapMutations, mapState } from "vuex";

export default {
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
  watch: {
    saving(newValue, oldValue) {
      if (oldValue && !newValue && !this.saveError) {
        this.closeModal();
      }
    }
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
      closeModal: "closeModal",
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
