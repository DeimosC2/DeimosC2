<template>
  <card type="task">
    <div class="row" slot="header">
      <div class="col-lg-4 col-12">
        <h4 class="card-title">{{ $t("settings.view-log-file") }}</h4>
      </div>
      <div class="col-lg-8 col-8">
        <div class="pull-right">
          <base-button
            class="action-button"
            :title="$t('logs.download') + activeTab + '.log'"
            @click="downloadFile()"
          >
            <i class="fas fa-file-download mr-2"></i> {{ $t("logs.download") }} {{ activeTab }}.log
          </base-button>
        </div>
      </div>
    </div>
    <ul class="nav nav-tabs">
      <li class="nav-item">
        <span
          style="cursor: pointer"
          class="nav-link btn-link"
          :class="{ active: activeTab === 'error' }"
          @click="activeTab = 'error'"
          >{{ $t("logs.error") }}</span
        >
      </li>
      <li class="nav-item">
        <span
          style="cursor: pointer"
          class="nav-link btn-link"
          :class="{ active: activeTab === 'backup' }"
          @click="activeTab = 'backup'"
          >{{ $t("logs.backup") }}</span
        >
      </li>
      <li class="nav-item">
        <span
          style="cursor: pointer"
          class="nav-link btn-link"
          :class="{ active: activeTab === 'commands' }"
          @click="activeTab = 'commands'"
          >{{ $t("logs.commands") }}</span
        >
      </li>
      <li class="nav-item">
        <span
          style="cursor: pointer"
          class="nav-link btn-link"
          :class="{ active: activeTab === 'module' }"
          @click="activeTab = 'module'"
          >{{ $t("logs.module") }}</span
        >
      </li>
    </ul>
    <div class="tab-content">
      <div class="tab-pane active">
        <LogReader :file="activeTab" />
      </div>
    </div>
  </card>
</template>

<script>
import { mapState } from "vuex";
import LogReader from "../../components/LogReader";
import { saveAsFile } from "../../plugins/c2/message-routes/misc/mixin";

export default {
  components: {
    LogReader
  },
  data() {
    return {
      activeTab: "error"
    };
  },
  computed: {
    ...mapState({
      logs: state => state.admin.logs
    })
  },
  methods: {
    downloadFile() {
      saveAsFile(this.logs, `${this.activeTab}.log`, "text/plain");
    }
  }
};
</script>
