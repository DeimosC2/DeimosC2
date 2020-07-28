<template>
  <div class="row">
    <div class="col-lg-6">
      <AgentInfo :agent="agent" />
    </div>
    <div class="col-lg-5 offset-lg-1">
      <AgentHeartBeat :agent="agent" />
      <FileSelector :files="agentFiles" @upload="upload" />
    </div>
    <div class="col-lg-12">
      <ul class="nav nav-tabs">
        <li class="nav-item">
          <span
            style="cursor: pointer"
            class="nav-link btn-link"
            :class="{ active: activeTab === 'term' }"
            @click="activeTab = 'term'"
            >{{ $t("agents.terminal") }}</span
          >
        </li>
        <li class="nav-item">
          <span
            style="cursor: pointer"
            class="nav-link btn-link"
            :class="{ active: activeTab === 'files' }"
            @click="activeTab = 'files'"
            >{{ $t("agents.FileBrowser") }}</span
          >
        </li>
        <li class="nav-item">
          <span
            style="cursor: pointer"
            class="nav-link btn-link"
            :class="{ active: activeTab === 'loot' }"
            @click="activeTab = 'loot'"
            >{{ $t("agents.Loot") }}</span
          >
        </li>
        <li class="nav-item">
          <span
            style="cursor: pointer"
            class="nav-link btn-link"
            :class="{ active: activeTab === 'lootFiles' }"
            @click="activeTab = 'lootFiles'"
            >{{ $t("agents.loot-files") }}</span
          >
        </li>
        <li class="nav-item">
          <span
            style="cursor: pointer"
            class="nav-link btn-link"
            :class="{ active: activeTab === 'comments' }"
            @click="activeTab = 'comments'"
            >{{ $t("agents.comments") }}</span
          >
        </li>
      </ul>
      <div class="tab-content">
        <div class="tab-pane" :class="{ active: activeTab === 'term' }">
          <Term :agent="agent" module="agents" :commands="commands" />
        </div>
        <div class="tab-pane" :class="{ active: activeTab === 'files' }">
          <div class="card card-task">
            <div class="card-body">
              <div class="table-responsive-sm">
                <FileBrowser
                  v-if="activeTab === 'files'"
                  module="agents"
                  :credentials="agent.Key"
                  startPoint="./"
                  :hideDates="true"
                  :hideRemove="true"
                />
              </div>
            </div>
          </div>
        </div>
        <div class="tab-pane" :class="{ active: activeTab === 'loot' }">
          <div class="card card-task">
            <div class="card-body">
              <LootTable :agent-key="agent.Key" v-if="activeTab === 'loot'" />
            </div>
          </div>
        </div>
        <div class="tab-pane" :class="{ active: activeTab === 'lootFiles' }">
          <div class="card card-task">
            <div class="card-body">
              <LootFiles v-if="activeTab === 'lootFiles'" :agent="agent.Key" />
            </div>
          </div>
        </div>
        <div class="tab-pane" :class="{ active: activeTab === 'comments' }">
          <Comments :agent="agent.Key" />
        </div>
      </div>
    </div>
  </div>
</template>
<script>
import { mapState, mapGetters, mapActions, mapMutations } from "vuex";

import AgentCommands from "@C2/plugins/jquery-terminal/agentCommands";
import AgentInfo from "./Agent/AgentInfo.vue";
import AgentHeartBeat from "./Agent/AgentHeartBeat.vue";
import Term from "../components/Term";
import FileSelector from "../components/FileSelector";
import FileBrowser from "../components/FileBrowser";
import LootTable from "./Loot/LootTable";
import LootFiles from "./Loot/LootFiles";
import Comments from "./Agent/Comments";

export default {
  data() {
    return {
      agentUUID: this.$route.params.agentUUID,
      commands: null,
      activeTab: "term"
    };
  },
  computed: {
    ...mapState({
      debug: "debug",
      initialized: state => state.agents.initialized,
      agentFiles: state => state.agents.filesToUpload,
      modulesSettings: state => state.agents.modulesSettings
    }),
    ...mapGetters({
      getAgentByKey: "agents/getAgentByKey"
    }),
    agent() {
      return this.getAgentByKey(this.agentUUID);
    },
    modulesSettingsForThisOS() {
      const result = {};
      Object.keys(this.modulesSettings).forEach(key => {
        if (this.modulesSettings[key].OS.includes(this.agent.OS)) {
          result[key] = this.modulesSettings[key];
        }
      });
      return result;
    }
  },
  components: {
    AgentInfo,
    AgentHeartBeat,
    Term,
    FileSelector,
    FileBrowser,
    LootTable,
    LootFiles,
    Comments
  },
  watch: {
    modulesSettings() {
      this.commands.$setModulesConfig(this.modulesSettingsForThisOS);
    }
  },
  methods: {
    upload(files) {
      this.$logging(`FileSelector::upload():uploading files ${files}`, this.debug);

      files.forEach(file => {
        const reader = new FileReader();
        reader.onloadend = () => {
          const b64 = reader.result.replace(/^data:.+;base64,/, "");
          this.sendJob({
            name: this.agent.Key,
            action: "upload",
            options: ["cwd", file.name, b64]
          });
        };
        reader.readAsDataURL(file);
        this.$notify({ type: "success", message: `Uploading "${file.name}"` });
      });
      this.clearFiles();
    },
    ...mapActions({
      register: "agents/registerAgent",
      deregister: "agents/deregisterAgent",
      sendJob: "agents/sendJob",
      listLootFiles: "loot/listLootFiles",
      listAgentLoot: "loot/listAgentLoot",
      getModulesSettings: "agents/getModulesSettings"
    }),
    ...mapMutations({
      clearFiles: "agents/clearFiles",
      clearCache: "loot/clearLootCache"
    })
  },
  created() {
    this.register(this.agentUUID);
  },
  beforeMount() {
    this.commands = new AgentCommands(this.agent.Key);
    if (!this.modulesSettings.length) {
      this.getModulesSettings();
    } else {
      this.commands.$setModulesConfig(this.modulesSettingsForThisOS);
    }
  },
  beforeRouteLeave(to, from, next) {
    this.deregister(this.agentUUID);
    this.clearCache();
    next();
  }
};
</script>
