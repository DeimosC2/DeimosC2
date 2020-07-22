<template>
  <card type="task" :title="$t('settings.settings')">
    <div class="row">
      <div class="col-lg-3 offset-lg-3">
        <h5>
          <toggle-button
            v-model="debug"
            class="mr-2"
            v-tooltip="$t('settings.debug-mode-tooltip')"
            :sync="true"
          />
          {{ $t("settings.debug-mode") }}
        </h5>
      </div>
      <div class="col-lg-3">
        <h5>
          <toggle-button
            v-model="experimental"
            class="mr-2"
            v-tooltip="$t('settings.experimental-tooltip')"
            :sync="true"
          />
          {{ $t("settings.experimental") }}
        </h5>
      </div>
    </div>
    <div class="row">
      <div class="col-lg-5 offset-lg-3 text-center">
        <h5>{{ $t("settings.env") }}</h5>
        <select v-model="env" class="select-env" v-tooltip="$t('settings.env-tooltip')">
          <option v-for="item in environments" :value="item" :key="item">{{ item }}</option>
        </select>
      </div>
    </div>
  </card>
</template>

<script>
import { mapState, mapMutations } from "vuex";

export default {
  data() {
    return {
      environments: ["Dev", "Prod"]
    };
  },
  computed: {
    ...mapState({
      debugState: "debug",
      experimentalState: "experimental",
      envState: "env"
    }),
    debug: {
      get() {
        return this.debugState;
      },
      set() {
        this.toggleDebug();
      }
    },
    experimental: {
      get() {
        return this.experimentalState;
      },
      set() {
        this.toggleExperimental();
      }
    },
    env: {
      get() {
        return this.envState;
      },
      set(_var) {
        this.setEnv(_var);
      }
    }
  },
  methods: {
    ...mapMutations({
      toggleDebug: "toggleDebug",
      toggleExperimental: "toggleExperimental",
      setEnv: "setEnv"
    })
  }
};
</script>
<style scoped>
.select-env {
  background: transparent;
  width: 200px;
  color: #fff;
}
</style>
