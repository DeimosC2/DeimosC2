<template>
  <div class="row">
    <div class="col-12">
      <card title="Loot" v-if="initialized">
        <div class="row" slot="header">
          <div class="col-lg-4 col-12">
            <h4 class="card-title">{{ $t("sidebar.loot") }}</h4>
          </div>
          <div class="col-lg-8 col-12">
            <div class="pull-right">
              <base-button type="success" class="mr-3 action-button" @click="addPassword">
                {{ $t("loot.add-password") }}
              </base-button>
              <base-button type="primary" @click="addLoot" class="action-button">
                {{ $t("loot.manually-add-loot") }}
              </base-button>
            </div>
          </div>
        </div>

        <ul class="nav nav-tabs">
          <li class="nav-item">
            <span
              style="cursor: pointer"
              class="nav-link btn-link"
              :class="{ active: activeTab === 'list' }"
              @click="activeTab = 'list'"
              >{{ $t("loot.loot") }}</span
            >
          </li>
          <li class="nav-item">
            <span
              style="cursor: pointer"
              class="nav-link btn-link"
              :class="{ active: activeTab === 'files' }"
              @click="activeTab = 'files'"
              >{{ $t("loot.loot-files") }}</span
            >
          </li>
        </ul>
        <div class="tab-content">
          <div class="tab-pane" :class="{ active: activeTab === 'list' }">
            <LootTable v-if="initialized" />
          </div>
          <div class="tab-pane" :class="{ active: activeTab === 'files' }">
            <div class="row">
              <div class="col-12">
                <LootFiles v-if="activeTab === 'files'" />
              </div>
            </div>
          </div>
        </div>
      </card>
    </div>
  </div>
</template>
<script>
import { mapActions, mapMutations, mapState } from "vuex";
import LootTable from "./Loot/LootTable";
import LootFiles from "./Loot/LootFiles";

export default {
  data() {
    return {
      activeTab: "list"
    };
  },
  components: {
    LootTable,
    LootFiles
  },
  computed: {
    ...mapState({
      initialized: state => state.agents.initialized
    })
  },
  methods: {
    addLoot() {
      this.openModal({ type: "addLoot", data: {} });
    },
    addPassword() {
      this.openModal({ type: "addLootPassword", data: {} });
    },
    ...mapActions({
      openModal: "openModal"
    }),
    ...mapMutations({
      clearCache: "loot/clearLootCache"
    })
  },
  beforeRouteLeave(to, from, next) {
    this.clearCache();
    next();
  }
};
</script>
