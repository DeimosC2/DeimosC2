<template>
  <div class="row">
    <card type="login" style="width: 20rem;" class="col-lg-4 offset-lg-3">
      <img slot="image" class="card-img-top" src="/img/login-logo.png" alt="DeimosC2 Logo" />
      <h4 class="card-title">SetUp Admin Account</h4>
      <slot>
        <base-input
          type="text"
          placeholder="Username"
          addonLeftIcon="fa fa-user"
          v-model="user.username"
          @input="$v.user.username.$touch()"
          @blur="$v.user.username.$touch()"
          :class="{ 'has-danger': usernameErrors.length }"
        >
          <template slot="validationErrors" v-if="usernameErrors.length">
            {{ usernameErrors.join(" ") }}
          </template>
        </base-input>

        <base-input
          type="password"
          placeholder="Password"
          addonLeftIcon="fa fa-lock"
          v-model="user.password"
          @input="$v.user.password.$touch()"
          @blur="$v.user.password.$touch()"
          :class="{ 'has-danger': passwordErrors.length }"
        >
          <template slot="validationErrors" v-if="passwordErrors.length">
            {{ passwordErrors.join(" ") }}
          </template>
        </base-input>

        <div class="row">
          <div class="col-lg-7">
            <base-input
              type="number"
              placeholder="Password length"
              addonLeftIcon="fa fa-lock"
              v-model="user.passlength"
              @input="$v.user.passlength.$touch()"
              @blur="$v.user.passlength.$touch()"
              :class="{ 'has-danger': passlengthErrors.length }"
            >
              <template slot="validationErrors" v-if="passlengthErrors.length">
                {{ passlengthErrors.join(" ") }}
              </template>
            </base-input>
          </div>
          <div class="col-lg-5 text-white mt-2">
            MFA <toggle-button v-model="user.mfa" :sync="true" class="mr-2" />
          </div>
        </div>
      </slot>

      <slot name="footer">
        <base-button
          type="primary"
          class="pull-right"
          :disabled="$v.validationGroup.$invalid"
          @click="createAccount()"
          @keyup.enter="createAccount()"
        >
          Create an account
        </base-button>
      </slot>
    </card>
  </div>
</template>
<script>
import { required, alphaNum, numeric } from "vuelidate/lib/validators";
import { mapActions } from "vuex";

export default {
  props: {
    source: String
  },
  data() {
    return {
      user: {
        username: "",
        password: "",
        mfa: false,
        passlength: null
      }
    };
  },
  validations: {
    user: {
      username: { required, alphaNum },
      password: { required },
      passlength: { required, numeric }
    },
    validationGroup: ["user.username", "user.password", "user.passlength"]
  },
  computed: {
    usernameErrors() {
      const errors = [];
      if (!this.$v.user.username.$dirty) return errors;
      if (!this.$v.user.username.alphaNum) errors.push("Invalid Name.");
      if (!this.$v.user.username.required) errors.push("Name is required.");
      return errors;
    },
    passwordErrors() {
      const errors = [];
      if (!this.$v.user.password.$dirty) return errors;
      if (!this.$v.user.password.required) errors.push("Password is required.");
      return errors;
    },
    passlengthErrors() {
      const errors = [];
      if (!this.$v.user.passlength.$dirty) return errors;
      if (!this.$v.user.passlength.required) errors.push("Password length is required.");
      if (!this.$v.user.passlength.numeric) errors.push("Password length should be a number");
      return errors;
    }
  },
  methods: {
    createAccount() {
      if (!this.$v.validationGroup.$invalid) {
        this.user.passlength = parseInt(this.user.passlength, 10);
        this.doCreateAccount(this.user);
      }
    },
    ...mapActions({
      doCreateAccount: "admin/createAccount"
    })
  }
};
</script>
<style></style>
