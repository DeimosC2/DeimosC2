<template>
  <card type="task">
    <div class="custom-file">
      <input
        type="file"
        class="custom-file-input"
        id="customFile"
        ref="file"
        @change="prepareFiles"
        :value="files"
        :multiple="multiple"
      />
      <div class="custom-file-label" for="customFile">
        <template v-if="selectedFiles.length < 1">{{ $t("file-browser.choose-file") }}</template>
        <template v-if="selectedFiles.length > 0 && showUploadButton"
          >{{ $t("file-browser..selected-files") }}:</template
        >
      </div>
      <div v-if="selectedFiles.length">
        <span
          class="btn btn-simple btn-sm btn-primary"
          v-for="(item, index) in selectedFiles"
          @click="removeFile(index)"
          :key="item.name"
        >
          {{ shortName(item.name) }} ({{ prettyBytes(item.size) }}) x</span
        >
      </div>
    </div>
    <button
      class="btn btn-success mt-2"
      :disabled="selectedFiles.length < 1"
      @click="upload()"
      v-if="showUploadButton"
    >
      <i class="fa fa-upload"></i> {{ $t("buttons.upload") }}
    </button>
  </card>
</template>

<script>
const prettyBytes = require("pretty-bytes");

export default {
  props: {
    files: {
      Type: Array,
      default: () => {
        return [];
      }
    },
    showUploadButton: {
      Type: Boolean,
      default: true
    },
    multiple: {
      Type: Boolean,
      default: true
    }
  },
  data() {
    return {
      selectedFiles: []
    };
  },
  methods: {
    upload() {
      this.$emit("upload", this.selectedFiles);
      this.selectedFiles = [];
    },
    prepareFiles(event) {
      if (!this.multiple) {
        this.selectedFiles = [];
      }
      Object.keys(event.target.files).forEach(index => {
        this.selectedFiles.push(event.target.files[index]);
      });
      this.$emit("selected", this.selectedFiles);
    },
    prettyBytes(size) {
      return prettyBytes(size);
    },
    shortName(name) {
      return name.length > 11 ? `${name.substr(0, 5)}...${name.substr(-5, 5)}` : name;
    },
    removeFile(index) {
      this.selectedFiles.splice(index, 1);
      this.$emit("selected", this.selectedFiles);
    }
  }
};
</script>
<style scoped></style>
