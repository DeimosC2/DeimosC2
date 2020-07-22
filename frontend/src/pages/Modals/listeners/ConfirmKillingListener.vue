<template>
  <div>
    <base-alert type="danger">
      {{ $t("listeners.you_are_going_to_kill") }} "{{ listener.Name }}".<br />
      <span v-html="$t('listeners.killing_warning')" />
    </base-alert>
    {{ $t("buttons.are_you_sure") }}
    <base-checkbox v-model="verified">{{ $t("buttons.verify") }}</base-checkbox>
    <div class="pull-right">
      <base-button type="danger" :disabled="!verified" @click="killListener">
        {{ $t("buttons.confirm") }}
      </base-button>
    </div>
  </div>
</template>

<script>
import { mapActions } from "vuex";
import BaseCheckbox from "../../../components/BaseCheckbox";

export default {
  name: "ConfirmKillingListener",
  components: { BaseCheckbox },
  props: {
    listener: {
      required: true,
      type: Object
    }
  },
  data() {
    return {
      verified: false
    };
  },
  methods: {
    killListener() {
      this.doKillListener(this.listener);
      this.closeModal();
    },
    ...mapActions({
      closeModal: "closeModal",
      doKillListener: "listeners/killListener"
    })
  }
};
</script>

<style scoped></style>
