<template>
  <div>
    <base-alert type="danger" v-if="saveError">{{ saveError }}</base-alert>
    <form ref="form">
      <div class="row">
        <div class="col-lg-12">Type: {{ listener.LType }}</div>
      </div>
      <Form
        v-if="listener && settings"
        :config="settings[listener.LType]"
        :Listener.sync="listener"
        @validate="validate"
        ref="configForm"
      />

      <div class="pull-right">
        <base-button
          :loading="saving"
          type="primary"
          :disabled="invalid || saving"
          @click="sendListener"
        >
          {{ $t("buttons.save") }}
        </base-button>
      </div>
    </form>
  </div>
</template>

<script>
import { mapActions, mapMutations, mapState } from "vuex";
import Form from "../../Listeners/Form";

export default {
  props: {
    listener: {
      required: true,
      type: Object
    }
  },
  data() {
    return {
      invalid: false
    };
  },
  components: {
    Form
  },
  computed: {
    ...mapState({
      debug: "debug",
      settings: state => state.listeners.settings,
      saving: state => state.listeners.saving,
      saveError: state => state.listeners.saveError
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
    sendListener() {
      if (!this.invalid) {
        this.clearSaver();
        this.startSaving(true);
        this.editListener(this.listener);
      }
    },
    validate(val) {
      this.invalid = val;
    },
    addDefaultValues(model, settings) {
      Object.keys(settings).forEach(item => {
        if (!model[item]) {
          if (!settings[item].type) {
            // eslint-disable-next-line
            model[item] = {};
            this.addDefaultValues(model[item], settings[item]);
          } else {
            // eslint-disable-next-line
            model[item] = settings[item].default;
          }
        }
      });
    },
    ...mapActions({
      editListener: "listeners/editListener",
      closeModal: "closeModal"
    }),
    ...mapMutations({
      startSaving: "listeners/saving",
      clearSaver: "listeners/clearSaver"
    })
  },
  created() {
    if (this.settings) {
      this.addDefaultValues(this.listener, this.settings[this.listener.LType]);
    }
  },
  beforeDestroy() {
    this.clearSaver();
  }
};
</script>
