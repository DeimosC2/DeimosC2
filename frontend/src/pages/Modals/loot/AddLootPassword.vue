<template>
  <div>
    <base-alert type="danger" v-if="saveError">{{ saveError }}</base-alert>
    <base-input
      type="text"
      label="Password"
      v-model="Loot['password']"
      @focus="$v.Loot.password.$touch"
      @input="validate"
      @change="validate"
      @keyup.enter.native="savePassword()"
      :class="{ 'has-danger': hasErrors('password') }"
    >
      <template slot="validationErrors" v-if="hasErrors('password')">
        {{ getErrors("password") }}
      </template>
    </base-input>

    <base-input
      type="text"
      label="Hash"
      v-model="Loot['hash']"
      @focus="$v.Loot.hash.$touch"
      @input="validate"
      @change="validate"
      @keyup.enter.native="savePassword()"
      :class="{ 'has-danger': hasErrors('hash') }"
    >
      <template slot="validationErrors" v-if="hasErrors('hash')">
        {{ getErrors("hash") }}
      </template>
    </base-input>

    <div class="pull-right">
      <base-button
        :loading="saving"
        type="primary"
        :disabled="invalid || saving"
        @click="savePassword"
      >
        {{ $t("buttons.save") }}
      </base-button>
    </div>
  </div>
</template>

<script>
import { mapActions, mapMutations, mapState } from "vuex";
import { required } from "vuelidate/lib/validators";

export default {
  name: "AddLootPassword",
  data() {
    return {
      invalid: true,
      Loot: {
        password: null,
        hash: null
      }
    };
  },
  validations() {
    return {
      Loot: {
        password: { required },
        hash: { required }
      },
      validationGroup: ["Loot"]
    };
  },
  computed: {
    ...mapState({
      saving: state => state.loot.saving,
      saveError: state => state.loot.saveError
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
    savePassword() {
      this.clearSaver();
      this.startAdding(true);
      this.addPasswordHash(this.Loot);
    },
    validate() {
      this.invalid = this.$v.validationGroup.$invalid;
    },
    hasErrors(name) {
      if (!this.$v.Loot[name].$dirty) return false;
      return this.$v.Loot[name].$invalid;
    },
    getErrors(name) {
      return this.$v.Loot[name].$invalid ? "Invalid" : "";
    },
    ...mapActions({
      addPasswordHash: "loot/addPasswordHash",
      closeModal: "closeModal"
    }),
    ...mapMutations({
      startAdding: "loot/saving",
      clearSaver: "loot/clearSaver"
    })
  },
  beforeDestroy() {
    this.clearSaver();
  }
};
</script>
