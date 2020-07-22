<template>
  <div>
    <base-alert type="danger" v-if="saveError">{{ saveError }}</base-alert>
    <div class="row">
      <div class="col-lg-12">
        <div class="form-group">
          <label class="control-label">Agent</label>
          <div class="text-danger" v-if="hasErrors('agentKey')">
            {{ getErrors("agentKey") }}
          </div>
          <select
            v-model="Loot['agentKey']"
            :error-messages="getErrors('agentKey')"
            @change="validate()"
            @focus="$v.Loot.agentKey.$touch"
            class="type-dropdown"
            :class="{ 'has-danger': hasErrors('agentKey') }"
          >
            <option :value="null" disabled selected>Agent</option>
            <option v-for="item in agents" :value="item.value" :key="item.value">{{
              item.text
            }}</option>
          </select>
        </div>
      </div>
    </div>
    <div class="row">
      <div class="col-lg-6">
        <base-input
          type="text"
          label="User"
          v-model="Loot['user']"
          @focus="$v.Loot.user.$touch"
          @input="validate"
          @change="validate"
          @keyup.enter.native="addLoot()"
          :class="{ 'has-danger': hasErrors('user') }"
        >
          <template slot="validationErrors" v-if="hasErrors('user')">
            {{ getErrors("user") }}
          </template>
        </base-input>
      </div>
      <div class="col-lg-6">
        <base-input
          type="text"
          label="Password"
          v-model="Loot['password']"
          @focus="$v.Loot.password.$touch"
          @input="validate"
          @change="validate"
          @keyup.enter.native="addLoot()"
          :class="{ 'has-danger': hasErrors('password') }"
        >
          <template slot="validationErrors" v-if="hasErrors('password')">
            {{ getErrors("password") }}
          </template>
        </base-input>
      </div>
    </div>
    <div class="row">
      <div class="col-lg-12">
        <base-input
          type="text"
          label="Hash"
          v-model="Loot['hash']"
          @focus="$v.Loot.hash.$touch"
          @input="validate"
          @change="validate"
          @keyup.enter.native="addLoot()"
          :class="{ 'has-danger': hasErrors('hash') }"
        >
          <template slot="validationErrors" v-if="hasErrors('hash')">
            {{ getErrors("hash") }}
          </template>
        </base-input>
      </div>
    </div>
    <div class="row">
      <div class="col-lg-6">
        <base-input
          type="text"
          label="Host"
          v-model="Loot['host']"
          @focus="$v.Loot.host.$touch"
          @input="validate"
          @change="validate"
          @keyup.enter.native="addLoot()"
          :class="{ 'has-danger': hasErrors('host') }"
        >
          <template slot="validationErrors" v-if="hasErrors('host')">
            {{ getErrors("host") }}
          </template>
        </base-input>
      </div>
      <div class="col-lg-6">
        <base-input
          type="text"
          label="Domain"
          v-model="Loot['domain']"
          @focus="$v.Loot.domain.$touch"
          @input="validate"
          @change="validate"
          @keyup.enter.native="addLoot()"
          :class="{ 'has-danger': hasErrors('domain') }"
        >
          <template slot="validationErrors" v-if="hasErrors('domain')">
            {{ getErrors("domain") }}
          </template>
        </base-input>
      </div>
    </div>
    <div class="row">
      <div class="col-lg-6">
        <base-input
          type="text"
          label="Cred Type"
          v-model="Loot['credtype']"
          @focus="$v.Loot.credtype.$touch"
          @input="validate"
          @change="validate"
          @keyup.enter.native="addLoot()"
          :class="{ 'has-danger': hasErrors('credtype') }"
        >
          <template slot="validationErrors" v-if="hasErrors('credtype')">
            {{ getErrors("credtype") }}
          </template>
        </base-input>
      </div>
      <div class="col-lg-6">
        <label class="control-label">Webshell </label><br />
        <toggle-button v-model="Loot['Webshell']" class="mr-2" :sync="true" />
      </div>
    </div>

    <div class="pull-right">
      <base-button
        :loading="saving"
        type="primary"
        :disabled="invalid || saving"
        @click="addLoot()"
      >
        Save
      </base-button>
    </div>
  </div>
</template>

<script>
import { mapActions, mapMutations, mapState } from "vuex";
import { required } from "vuelidate/lib/validators";

export default {
  name: "AddLootPassword",
  data() {
    return {
      invalid: true,
      Loot: {
        agentKey: null,
        user: null,
        password: null,
        hash: null,
        credtype: null,
        host: null,
        domain: null,
        webshell: false
      },
      credTypes: ["SAM", "LSA", "LSASS"]
    };
  },
  validations() {
    return {
      Loot: {
        agentKey: { required },
        user: { required },
        password: { required },
        hash: { required },
        credtype: { required },
        host: { required },
        domain: { required }
      },
      validationGroup: ["Loot"]
    };
  },
  computed: {
    agents() {
      return this.rowAgents.map(item => {
        return { text: item.Key, value: item.Key };
      });
    },
    ...mapState({
      saving: state => state.loot.saving,
      saveError: state => state.loot.saveError,
      rowAgents: state => state.agents.agents
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
    addLoot() {
      this.clearSaver();
      // this.startAdding(true);
      this.doAddLoot(this.Loot);
    },
    validate() {
      this.invalid = this.$v.validationGroup.$invalid;
    },
    hasErrors(name) {
      if (!this.$v.Loot[name].$dirty) return false;
      return this.$v.Loot[name].$invalid;
    },
    getErrors(name) {
      return this.$v.Loot[name].$invalid ? "Invalid" : "";
    },
    ...mapActions({
      doAddLoot: "loot/addLootManually",
      closeModal: "closeModal"
    }),
    ...mapMutations({
      startAdding: "loot/saving",
      clearSaver: "loot/clearSaver"
    })
  },
  beforeDestroy() {
    this.clearSaver();
  }
};
</script>
