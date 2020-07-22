<template>
  <div>
    <base-alert type="danger" v-if="saveError">{{ saveError }}</base-alert>
    <base-input
      type="text"
      :label="$t('users.login')"
      v-model="user['username']"
      @focus="$v.user.username.$touch"
      @input="validate"
      @change="validate"
      @keyup.enter.native="updateUser()"
      :class="{ 'has-danger': hasErrors('username') }"
    >
      <template slot="validationErrors" v-if="hasErrors('username')">
        {{ getErrors("username") }}
      </template>
    </base-input>

    <base-input type="password" :label="$t('users.password')" v-model="password"> </base-input>

    <div class="row">
      <div class="col-lg-6">
        {{ $t("users.admin") }}
        <toggle-button v-model="user['isAdmin']" class="mr-2" :sync="true" />
      </div>
      <div class="col-lg-6">
        <div class="pull-right">
          <base-button
            :loading="saving"
            type="primary"
            :disabled="invalid || saving"
            @click="updateUser()"
          >
            {{ $t("buttons.update") }}
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
  name: "EditUser",
  props: {
    user: {
      Type: Object,
      required: true
    }
  },
  data() {
    return {
      invalid: false,
      password: ""
    };
  },
  validations() {
    return {
      user: {
        username: { required }
      },
      validationGroup: ["user"]
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
    updateUser() {
      this.clearSaver();
      this.user.password = this.password;
      this.editUser(this.user);
      this.closeModal();
    },
    validate() {
      this.invalid = this.$v.validationGroup.$invalid;
    },
    hasErrors(name) {
      if (!this.$v.user[name].$dirty) return false;
      return this.$v.user[name].$invalid;
    },
    getErrors(name) {
      return this.$v.user[name].$invalid ? "Invalid" : "";
    },

    ...mapActions({
      closeModal: "closeModal",
      editUser: "admin/editUser"
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
