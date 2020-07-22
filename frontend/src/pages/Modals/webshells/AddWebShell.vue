<template>
  <div>
    <base-alert type="danger" v-if="saveError">{{ saveError }}</base-alert>
    <base-input
      type="text"
      label="URL"
      v-model="Shell['URL']"
      @focus="$v.Shell.URL.$touch"
      @input="validate"
      @change="validate"
      @keyup.enter.native="addShell()"
      :class="{ 'has-danger': hasErrors('URL') }"
    >
      <template slot="validationErrors" v-if="hasErrors('URL')">
        {{ getErrors("URL") }}
      </template>
    </base-input>

    <base-input
      type="text"
      label="AuthToken"
      v-model="Shell['AuthToken']"
      @focus="$v.Shell.AuthToken.$touch"
      @input="validate"
      @change="validate"
      @keyup.enter.native="addShell()"
      :class="{ 'has-danger': hasErrors('AuthToken') }"
    >
      <template slot="validationErrors" v-if="hasErrors('AuthToken')">
        {{ getErrors("AuthToken") }}
      </template>
    </base-input>

    <div class="pull-right">
      <base-button :loading="saving" type="primary" :disabled="invalid || saving" @click="addShell">
        {{ $t("buttons.save") }}
      </base-button>
    </div>
  </div>
</template>

<script>
import { mapActions, mapMutations, mapState } from "vuex";
import { required } from "vuelidate/lib/validators";

export default {
  name: "AddWebShell",
  data() {
    return {
      invalid: true,
      Shell: {
        URL: null,
        AuthToken: null
      }
    };
  },
  validations() {
    return {
      Shell: {
        URL: { required },
        AuthToken: { required }
      },
      validationGroup: ["Shell"]
    };
  },
  computed: {
    ...mapState({
      saving: state => state.webShells.saving,
      saveError: state => state.webShells.saveError
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
    addShell() {
      this.clearSaver();
      this.startAdding(true);
      this.initWebShell(this.Shell);
    },
    validate() {
      this.invalid = this.$v.validationGroup.$invalid;
    },
    hasErrors(name) {
      if (!this.$v.Shell[name].$dirty) return false;
      return this.$v.Shell[name].$invalid;
    },
    getErrors(name) {
      return this.$v.Shell[name].$invalid ? "Invalid" : "";
    },

    ...mapActions({
      initWebShell: "webShells/initWebShell",
      closeModal: "closeModal"
    }),
    ...mapMutations({
      startAdding: "webShells/saving",
      clearSaver: "webShells/clearSaver"
    })
  },
  beforeDestroy() {
    this.clearSaver();
  }
};
</script>
