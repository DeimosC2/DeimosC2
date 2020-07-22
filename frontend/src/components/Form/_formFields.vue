<template>
  <div>
    <div v-for="key in fields" v-bind:key="key">
      <template v-if="!config[key].type && Object.keys(config[key]).length">
        <button
          type="button"
          class="btn btn-link text-white-70 font-weight-normal"
          style="padding-left: 0"
          @click="toggle(key)"
        >
          {{ $t(`listeners.config.${key}`) }}:
          <i class="fas" :class="show[key] ? 'fa-angle-double-down' : 'fa-angle-double-right'"></i>
        </button>
        <form-fields
          v-show="show[key]"
          :fields="Object.keys(config[key])"
          :config="config[key]"
          :model="model[key]"
          :modelName="modelName + '|' + key"
          @validateForm="validate"
          :validator="validator"
        />
      </template>
      <template v-else>
        <template v-if="config[key].type === 'agent'">
          <div class="form-group">
            <label class="control-label">{{ $t(`listeners.config.${key}`) }}</label>
            <div class="text-danger" v-if="hasErrors(key)">
              {{ getErrors(key) }}
            </div>
            <select
              v-model="model[key]"
              :error-messages="getErrors(key)"
              @change="setIP(key)"
              class="type-dropdown"
              :class="{ 'has-danger': hasErrors(key) }"
            >
              <option :value="null" disabled selected>Agent</option>
              <option v-for="item in agents" :value="item.value" :key="item.value">{{
                item.text
              }}</option>
            </select>
          </div>
        </template>

        <template v-if="config[key].type === 'file' && shouldBeShown(config[key])">
          <div class="form-group">
            <label class="control-label">{{ $t(`listeners.config.${key}`) }}</label>
            <FileSelector
              @selected="attachFile(key, $event)"
              :showUploadButton="false"
              :multiple="false"
            />
          </div>
        </template>

        <template v-if="config[key].type === 'bool' && shouldBeShown(config[key])">
          <div class="form-group">
            <toggle-button v-model="model[key]" class="ml-2" :ref="key" :sync="true" />
            {{ $t(`listeners.config.${key}`) }}:
          </div>
        </template>

        <base-input
          v-if="
            ['number', 'string', 'float'].includes(config[key].type) && shouldBeShown(config[key])
          "
          v-model="model[key]"
          :label="$t(`listeners.config.${key}`)"
          :ref="key"
          @input="validate"
          @change="validate"
          @keyup.enter.native="validate"
          :type="getType(config[key].type)"
          :class="{ 'has-danger': hasErrors(key) }"
        >
          <template slot="validationErrors" v-if="hasErrors(key)">
            {{ getErrors(key) }}
          </template>
        </base-input>
      </template>
    </div>
  </div>
</template>

<script>
import { mapState, mapGetters } from "vuex";
import _ from "lodash";
import FileSelector from "../FileSelector";

export default {
  name: "formFields",
  props: {
    fields: {
      type: Array,
      required: true
    },
    config: {
      type: Object,
      required: true
    },
    model: {
      type: Object,
      required: true
    },
    modelName: {
      type: String
    },
    validator: {
      type: Object
    }
  },
  components: {
    FileSelector
  },
  data() {
    return {
      show: []
    };
  },
  computed: {
    agents() {
      return this.rowAgents.map(item => {
        return { text: item.Key, value: item.Key };
      });
    },
    ...mapState({
      rowAgents: state => state.agents.agents
    }),
    ...mapGetters({
      getAgentByKey: "agents/getAgentByKey"
    })
  },
  methods: {
    validate() {
      this.$emit("validateForm");
    },
    getErrors(key) {
      let model = this.validator;
      this.modelName.split("|").forEach(item => {
        model = model[item];
      });
      return model[key].$invalid ? "Invalid" : "";
    },
    hasErrors(key) {
      let model = this.validator;
      this.modelName.split("|").forEach(item => {
        model = model[item];
      });
      return model[key].$invalid;
    },
    attachFile(key, file) {
      file.forEach(item => {
        const reader = new FileReader();
        reader.onloadend = () => {
          this.model[key] = reader.result.replace(/^data:.+;base64,/, "");
          // this.model[key]  = { name: item.name, b64 }
        };
        reader.readAsDataURL(item);
      });
    },
    getType(type) {
      switch (type) {
        case "number":
          return "number";
        case "float":
          return "number";
        case "string":
          return "text";
        default:
          return "text";
      }
    },
    shouldBeShown(config) {
      if (!config.if) return true;
      let model = this.validator.Listener;
      config.if.split("|").forEach(item => {
        model = model[item];
      });
      return model.$model;
    },
    toggle(key) {
      if (this.show[key]) {
        this.show = _.omit(this.show, key);
      } else {
        this.$set(this.show, key, true);
      }
    },
    setIP(key) {
      const agent = this.getAgentByKey(this.model[key]);
      if (agent) {
        this.model.Host = agent.LocalIP;
      }
      this.validate();
    }
  }
};
</script>
