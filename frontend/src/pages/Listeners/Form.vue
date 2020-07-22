<template>
  <div class="row">
    <div class="col-lg-12">
      <form-fields
        :fields="Object.keys(config)"
        :config="config"
        :model="Listener"
        modelName="Listener"
        @validateForm="validate"
        :validator="$v"
      />
    </div>
  </div>
</template>

<script>
import { required } from "vuelidate/lib/validators";
import formFields from "../../components/Form/_formFields";

export default {
  name: "Form",
  props: {
    config: {
      type: Object
    },
    Listener: {
      type: Object
    }
  },
  components: {
    formFields
  },
  validations() {
    return {
      Listener: this.ListenerValidationSettings,
      validationGroup: ["Listener"]
    };
  },
  computed: {
    ListenerValidationSettings() {
      const validationConfig = {};
      this.extractValidationRules(validationConfig, this.config);
      return validationConfig;
    }
  },
  methods: {
    validate() {
      this.$emit("validate", this.$v.validationGroup.$invalid);
    },
    extractValidationRules(model, settings) {
      Object.keys(settings).forEach(item => {
        // eslint-disable-next-line
        model[item] = {};
        if (!settings[item].type) {
          // eslint-disable-next-line
          model[item] = {};
          this.extractValidationRules(model[item], settings[item]);
        } else if (settings[item].required) {
          // eslint-disable-next-line
          model[item].required = required;
        }
      });
    }
  }
};
</script>
