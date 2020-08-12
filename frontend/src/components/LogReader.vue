<template>
  <div class="logFile">
    <codemirror :value="logs" :options="cmOptions" />
  </div>
</template>

<script>
import { mapActions, mapState } from "vuex";

export default {
  name: "LogReader",
  props: {
    file: {
      type: String,
      required: true
    }
  },
  data() {
    return {
      cmOptions: {
        theme: "base16-dark",
        lineNumbers: true,
        line: true,
        mode: "text/x-sh"
      }
    };
  },
  watch: {
    file() {
      this.fetchData();
    }
  },
  computed: {
    ...mapState({
      logs: state => state.admin.logs
    })
  },
  methods: {
    fetchData() {
      this.getLogs(this.file);
    },
    ...mapActions({
      getLogs: "admin/getLogs"
    })
  },
  mounted() {
    this.fetchData();
  }
};
</script>
<style scoped>
.logFile {
  max-height: 80vh;
  overflow: scroll;
}
</style>
