<template>
  <div>
    <base-alert type="danger" v-if="saveError">{{ saveError }}</base-alert>

    <div class="row">
      <div class="col-lg-4">
        {{ $t("users.MFA") }}<toggle-button v-model="mfa" :sync="true" class="mr-2" />
      </div>
      <div class="col-lg-8">
        <div class="row">
          <div class="col-lg-4">
            {{ $t("users.password-length") }}
          </div>
          <div class="col-lg-8">
            <input type="number" v-model="passlength" class="form-control" />
          </div>
        </div>
      </div>
    </div>
    <div class="pull-right">
      <base-button
        :loading="saving"
        type="primary"
        :disabled="saving"
        @click="updateSettings"
        class="mt-3"
      >
        {{ $t("buttons.save") }}
      </base-button>
    </div>
  </div>
</template>

<script>
import { mapActions, mapMutations, mapState } from "vuex";

export default {
  name: "AddUser",
  data() {
    return {
      mfa: false,
      passlength: null
    };
  },
  computed: {
    ...mapState({
      saving: state => state.admin.saving,
      saveError: state => state.admin.saveError,
      rowMfa: state => state.admin.mfa,
      rowPasslength: state => state.admin.passlength
    })
  },
  watch: {
    saving(newValue, oldValue) {
      if (oldValue && !newValue && !this.saveError) {
        this.closeModal();
      }
    },
    rowPasslength() {
      this.passlength = this.rowPasslength;
      console.log("password changes", this.rowPasslength, this.passlength);
    },
    rowMfa() {
      this.mfa = this.rowMfa;
      console.log("mfa changes", this.rowMfa, this.mfa);
    }
  },
  methods: {
    updateSettings() {
      this.clearSaver();
      this.startSaving(true);
      this.updateAppSettings({ mfa: this.mfa, passlength: this.passlength });
    },
    ...mapActions({
      closeModal: "closeModal",
      getAppSettings: "admin/appSettings",
      updateAppSettings: "admin/updateAppSettings"
    }),
    ...mapMutations({
      startSaving: "admin/saving",
      clearSaver: "admin/clearSaver"
    })
  },
  mounted() {
    this.getAppSettings();
    this.mfa = this.rowMfa;
    this.passlength = this.rowPasslength;
  },
  beforeDestroy() {
    this.clearSaver();
  }
};
</script>
