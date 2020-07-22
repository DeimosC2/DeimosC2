<template>
  <div>
    <base-alert type="danger" v-if="saveError">{{ saveError }}</base-alert>
    <base-input
      type="text"
      :label="$t('users.login')"
      v-model="User['login']"
      @focus="$v.User.login.$touch"
      @input="validate"
      @change="validate"
      @keyup.enter.native="addUser()"
      :class="{ 'has-danger': hasErrors('login') }"
    >
      <template slot="validationErrors" v-if="hasErrors('login')">
        {{ getErrors("login") }}
      </template>
    </base-input>

    <base-input
      type="password"
      :label="$t('users.password')"
      v-model="User['password']"
      @focus="$v.User.password.$touch"
      @input="validate"
      @change="validate"
      @keyup.enter.native="addUser()"
      :class="{ 'has-danger': hasErrors('password') }"
    >
      <template slot="validationErrors" v-if="hasErrors('password')">
        {{ getErrors("password") }}
      </template>
    </base-input>

    <div class="row">
      <div class="col-lg-6">
        {{ $t("users.admin") }} <toggle-button v-model="User['admin']" class="mr-2" :sync="true" />
      </div>
      <div class="col-lg-6">
        <div class="pull-right">
          <base-button
            :loading="saving"
            type="primary"
            :disabled="invalid || saving"
            @click="addUser"
          >
            {{ $t("buttons.create") }}
          </base-button>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { mapActions, mapMutations, mapState } from "vuex";
import { required } from "vuelidate/lib/validators";

export default {
  name: "AddUser",
  data() {
    return {
      invalid: true,
      User: {
        login: null,
        password: null,
        admin: false
      }
    };
  },
  validations() {
    return {
      User: {
        login: { required },
        password: { required }
      },
      validationGroup: ["User"]
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
    addUser() {
      this.clearSaver();
      this.doAddUser(this.User);
    },
    validate() {
      this.invalid = this.$v.validationGroup.$invalid;
    },
    hasErrors(name) {
      if (!this.$v.User[name].$dirty) return false;
      return this.$v.User[name].$invalid;
    },
    getErrors(name) {
      return this.$v.User[name].$invalid ? "Invalid" : "";
    },

    ...mapActions({
      closeModal: "closeModal",
      doAddUser: "admin/addUser"
    }),
    ...mapMutations({
      clearSaver: "admin/clearSaver"
    })
  },
  beforeDestroy() {
    this.clearSaver();
  }
};
</script>
