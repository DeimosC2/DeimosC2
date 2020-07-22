<template>
  <div>
    <base-alert type="danger" v-if="saveError">{{ saveError }}</base-alert>
    <div class="row">
      <div class="col-lg-8">
        <select v-model="Loot['credtype']" required class="type-dropdown">
          <option v-for="item in CredTypes" :value="item" :key="item">{{ item }}</option>
        </select>
      </div>
      <div class="col-lg-4">
        <toggle-button v-model="Loot['webshell']" class="mr-2" :sync="true" />
        {{ $t("loot.webshell") }}
      </div>
    </div>
    <div class="row">
      <div class="col-lg-12">
        <div class="form-group" v-if="!Loot['webshell']">
          <label class="control-label">{{ $t("loot.agent") }}</label>
          <select v-model="Loot['agentKey']" class="type-dropdown">
            <option :value="null" disabled selected>{{ $t("loot.agent") }}</option>
            <option v-for="item in agents" :value="item.value" :key="item.value">{{
              item.text
            }}</option>
          </select>
        </div>
        <div class="form-group" v-if="Loot['webshell']">
          <label class="control-label">{{ $t("loot.webshell") }}</label>
          <select v-model="Loot['agentKey']" class="type-dropdown">
            <option :value="null" disabled selected>{{ $t("loot.webshell") }}</option>
            <option v-for="item in webshells" :value="item.value" :key="item.value">{{
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
          :label="$t('loot.userName')"
          v-model="Loot['userName']"
          @keyup.enter.native="addLoot()"
        />
      </div>
      <div class="col-lg-6">
        <base-input
          type="text"
          :label="$t('loot.password')"
          v-model="Loot['password']"
          @keyup.enter.native="addLoot()"
        />
      </div>
    </div>
    <div class="row">
      <div class="col-lg-12">
        <base-input
          type="text"
          :label="$t('loot.hash')"
          v-model="Loot['hash']"
          @keyup.enter.native="addLoot()"
        />
      </div>
    </div>
    <div class="row">
      <div class="col-lg-6">
        <base-input
          type="text"
          :label="$t('loot.host')"
          v-model="Loot['host']"
          @keyup.enter.native="addLoot()"
        />
      </div>
      <div class="col-lg-6">
        <base-input
          type="text"
          :label="$t('loot.domain')"
          v-model="Loot['domain']"
          @keyup.enter.native="addLoot()"
        />
      </div>
    </div>

    <div class="pull-right">
      <base-button :loading="saving" type="primary" :disabled="saving" @click="addLoot()">
        {{ $t("buttons.save") }}
      </base-button>
    </div>
  </div>
</template>

<script>
import { mapActions, mapMutations, mapState } from "vuex";

export default {
  name: "AddLootPassword",
  data() {
    return {
      Loot: {
        agentKey: null,
        userName: null,
        password: null,
        hash: null,
        credtype: "SAM",
        host: null,
        domain: null,
        webshell: false
      },
      CredTypes: ["SAM", "LSA", "LSASS"]
    };
  },
  computed: {
    agents() {
      return this.rowAgents.map(item => {
        return { text: item.Key, value: item.Key };
      });
    },
    webshells() {
      return this.rowWebshells.map(item => {
        return { text: item.UUID, value: item.UUID };
      });
    },
    ...mapState({
      saving: state => state.loot.saving,
      saveError: state => state.loot.saveError,
      rowAgents: state => state.agents.agents,
      rowWebshells: state => state.webShells.webShells
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
      this.startAdding(true);
      this.doAddLoot(this.Loot);
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
