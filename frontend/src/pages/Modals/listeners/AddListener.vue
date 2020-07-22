<template>
  <div>
    <base-alert type="danger" v-if="saveError">{{ saveError }}</base-alert>
    <form ref="form">
      <div class="row">
        <div class="col-lg-12">
          <select v-model="LType" required class="type-dropdown">
            <option :value="null" disabled selected>{{ $t("listeners.type") }}</option>
            <option v-for="item in listenerTypes" :value="item" :key="item">{{ item }}</option>
          </select>
        </div>
      </div>
      <Form
        v-if="LType && Listener"
        :config="settings[LType]"
        :Listener.sync="Listener"
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
          {{ $t("buttons.send") }}
        </base-button>
      </div>
    </form>
  </div>
</template>

<script>
import { mapState, mapActions, mapMutations } from "vuex";
import Form from "../../Listeners/Form";

export default {
  created() {
    this.Listener.Host = this.server;
  },
  components: {
    Form
  },
  data() {
    return {
      LType: null,
      invalid: true,
      Listener: {}
    };
  },
  computed: {
    ...mapState({
      server: state => state.server.hostname,
      settings: state => state.listeners.settings,
      saving: state => state.listeners.saving,
      saveError: state => state.listeners.saveError
    }),
    listenerTypes() {
      return Object.keys(this.settings);
    }
  },
  watch: {
    LType() {
      if (this.LType) {
        const newFormModel = {};
        this.extractDefaultValues(newFormModel, this.settings[this.LType]);
        this.Listener = newFormModel;
        this.Listener.LType = this.LType;
        this.$nextTick(() => {
          this.$refs.configForm.validate();
        });
      }
    },
    saving(newValue, oldValue) {
      if (oldValue && !newValue && !this.saveError) {
        this.closeModal();
      }
    }
  },
  methods: {
    validate(val) {
      this.invalid = val;
    },
    sendListener() {
      if (!this.invalid) {
        this.clearSaver();
        this.startSaving(true);
        this.createListener(this.Listener);
      }
    },
    extractDefaultValues(model, settings) {
      Object.keys(settings).forEach(item => {
        if (!settings[item].type) {
          // eslint-disable-next-line
            model[item] = {};
          this.extractDefaultValues(model[item], settings[item]);
        } else {
          // eslint-disable-next-line
            model[item] = settings[item].default;
        }
      });
    },
    ...mapActions({
      createListener: "listeners/createListener",
      closeModal: "closeModal"
    }),
    ...mapMutations({
      startSaving: "listeners/saving",
      clearSaver: "listeners/clearSaver"
    })
  },
  beforeDestroy() {
    this.clearSaver();
  }
};
</script>
