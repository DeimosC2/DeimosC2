<template>
  <div class="row mfa">
    <card type="login" style="width: 20rem;" class="col-lg-4 offset-lg-3">
      <img
        v-if="qrCode"
        slot="image"
        class="card-img-top"
        :src="'data:image/svg+xml;base64,' + qrCode"
        alt="QR code"
      />
      <h4 class="card-title">Multi-Factor Authentication</h4>
      <slot>
        <base-alert type="danger" v-if="saveError">{{ saveError }}</base-alert>
        <base-input type="token" label="Token" v-model="Token"> </base-input>
      </slot>
      <slot name="footer">
        <base-button type="primary" @click="sendToken()">
          Continue
        </base-button>
      </slot>
    </card>
  </div>
</template>
<script>
import { mapActions, mapState } from "vuex";
import store from "../store";

export default {
  beforeRouteEnter(to, from, next) {
    if (!store.state.auth.mustEnterMFA) {
      next("/");
    } else {
      next();
    }
  },
  name: "MFA",
  data() {
    return {
      Token: null,
      saveError: null
    };
  },
  computed: {
    ...mapState({
      qrCode: state => state.auth.qrCode
    })
  },
  methods: {
    sendToken() {
      this.saveError = null;
      if (this.Token) {
        this.doSendToken(this.Token);
      } else {
        this.saveError = "Please, enter the code";
      }
    },
    ...mapActions({
      doSendToken: "sendToken"
    })
  }
};
</script>
