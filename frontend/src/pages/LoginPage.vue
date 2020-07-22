<template>
  <div class="row">
    <card type="login" style="width: 20rem;" class="col-lg-4 offset-lg-3">
      <img slot="image" class="card-img-top" src="/img/login-logo.png" alt="DeimosC2 Logo" />
      <h4 class="card-title">Login</h4>
      <slot>
        <base-input
          type="text"
          placeholder="Login"
          addonLeftIcon="fa fa-user"
          v-model="user.login"
          @input="$v.user.login.$touch()"
          @blur="$v.user.login.$touch()"
          @keyup.enter.native="performLogin()"
          :class="{ 'has-danger': loginErrors.length }"
        >
          <template slot="validationErrors" v-if="loginErrors.length">
            {{ loginErrors.join(" ") }}
          </template>
        </base-input>
        <base-input
          type="password"
          placeholder="Password"
          addonLeftIcon="fa fa-lock"
          v-model="user.password"
          @input="$v.user.password.$touch()"
          @blur="$v.user.password.$touch()"
          @keyup.enter.native="performLogin()"
          :class="{ 'has-danger': passwordErrors.length }"
        >
          <template slot="validationErrors" v-if="passwordErrors.length">
            {{ passwordErrors.join(" ") }}
          </template>
        </base-input>
      </slot>
      <slot name="footer">
        <base-button
          type="primary"
          class="pull-right"
          :disabled="$v.validationGroup.$invalid && !processingLogin"
          @click="performLogin()"
          @keyup.enter="performLogin()"
          :loading="processingLogin"
        >
          Login
        </base-button>
      </slot>
    </card>
  </div>
</template>
<script>
import { mapState, mapActions } from "vuex";
import { required, alphaNum } from "vuelidate/lib/validators";

export default {
  props: {
    source: String
  },
  data() {
    return {
      user: {
        login: "",
        password: ""
      }
    };
  },
  validations: {
    user: {
      login: { required, alphaNum },
      password: { required }
    },
    validationGroup: ["user.login", "user.password"]
  },
  computed: {
    ...mapState({
      loggedIn: state => state.auth.loggedIn,
      processingLogin: "processingLogin",
      env: "env"
    }),
    loginErrors() {
      const errors = [];
      if (!this.$v.user.login.$dirty) return errors;
      if (!this.$v.user.login.alphaNum) errors.push("Invalid Name.");
      if (!this.$v.user.login.required) errors.push("Name is required.");
      return errors;
    },
    passwordErrors() {
      const errors = [];
      if (!this.$v.user.password.$dirty) return errors;
      if (!this.$v.user.password.required) errors.push("Password is required.");
      return errors;
    }
  },
  methods: {
    ...mapActions({
      checkAuth: "checkAuth",
      openModal: "openModal"
    }),
    async performLogin() {
      if (!this.$v.validationGroup.$invalid) {
        await this.checkAuth({
          username: this.user.login,
          password: this.user.password
        }).then(() => {
          this.user.password = "";
          this.$v.$reset();
          this.$router.push("/");
        });
      }
    }
  }
};
</script>
<style></style>
