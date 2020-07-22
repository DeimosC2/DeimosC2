<template>
  <card type="task" :title="$t('settings.api-tester-title')">
    <div class="row">
      <div class="col-12">
        <Panel :title="$t('settings.api-tester-subtitle')">
          <div style="background-color: #27293d">
            <div class="row">
              <div class="col-12">
                <v-jsoneditor
                  v-model="textInput"
                  :options="options"
                  :plus="false"
                  height="400px"
                  class="editor"
                  @input="error = false"
                  @error="error = true"
                />
              </div>
            </div>
            <div class="row">
              <div class="col-6">
                <base-button
                  type="primary"
                  class="ml-lg-3 mb-2"
                  :disabled="error"
                  @click="sendInput"
                  >{{ $t("buttons.send") }}</base-button
                >
              </div>
              <div class="col-6">
                <base-button type="default" class="mr-lg-3 mb-2 pull-right" @click="resetInput">{{
                  $t("buttons.reset")
                }}</base-button>
              </div>
            </div>
          </div>
        </Panel>
      </div>
    </div>
  </card>
</template>

<script>
import { mapState } from "vuex";
import VJsoneditor from "v-jsoneditor";
import Panel from "../../components/Panel";

export default {
  data() {
    return {
      options: {
        modes: ["code", "tree"]
      },
      defaultInput: {
        Type: "Listeners",
        FunctionName: "List",
        Data: {}
      },
      textInput: "",
      error: false
    };
  },
  computed: {
    ...mapState({
      initialized: state => state.socket.SocketConnected
    })
  },
  methods: {
    resetInput() {
      this.textInput = this.defaultInput;
    },
    sendInput() {
      this.$socket.sendObj(this.textInput);
    }
  },
  mounted() {
    this.resetInput();
  },
  components: {
    VJsoneditor,
    Panel
  }
};
</script>

<style scoped>
#json {
  font-family: monospace;
  color: #fff;
  background: #27293d;
  width: 100%;
  width: -moz-available; /* WebKit-based browsers will ignore this. */
  width: -webkit-fill-available; /* Mozilla-based browsers will ignore this. */
  width: fill-available;
  /* min-height: 50px; */
}
.editor {
  background: #ffffff;
}
.jsoneditor-container.min-box {
  min-width: unset !important;
}
</style>
