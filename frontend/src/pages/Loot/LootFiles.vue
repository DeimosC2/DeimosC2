<template>
  <div class="table-responsive-sm">
    <FileBrowser
      module="loot"
      :credentials="agent"
      :startPoint="startPoint"
      :hideDates="true"
      :hideRemove="true"
      :hideUpload="true"
      uuid="loot"
    />
  </div>
</template>

<script>
import { mapMutations } from "vuex";
import FileBrowser from "../../components/FileBrowser";

export default {
  name: "LootFiles",
  props: {
    agent: {
      type: String,
      default: ""
    }
  },
  components: {
    FileBrowser
  },
  computed: {
    startPoint() {
      return this.agent !== "" ? `/looted/${this.agent}/` : "./";
    }
  },
  methods: {
    ...mapMutations({
      clearLootFilesCache: "loot/clearCache",
      setStartPoint: "loot/setStartPoint"
    })
  },
  mounted() {
    this.setStartPoint(this.startPoint);
  },
  beforeDestroy() {
    this.clearLootFilesCache();
  }
};
</script>
