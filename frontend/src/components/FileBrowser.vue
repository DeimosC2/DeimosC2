<template>
  <div>
    <div class="el-tree-node__content el-tree-header">
      <div style="width: 100%; margin-left: 10px;" class="row">
        <div class="col-12">
          <table style="width: 100%; table-layout:fixed;" class="table-responsive-sm">
            <tr>
              <td style="width: 50%;">
                <span>{{ $t("file-browser.file-folder") }}</span>
              </td>
              <td style="width: 18%;" class="small">
                <template v-if="!hideDates">{{ $t("file-browser.creation-time") }}</template>
              </td>
              <td style="width: 18%;" class="small">
                <template v-if="!hideDates">{{ $t("file-browser.last-access") }}</template>
              </td>
              <td style="width: 20%;" class="small">{{ $t("file-browser.last-modified") }}</td>
              <td style="width: 10%;" class="small">{{ $t("file-browser.size") }}</td>
              <td style="width: 14%;" class="small">{{ $t("file-browser.perms") }}</td>
              <td style="width: 20%;" class="small"></td>
            </tr>
          </table>
        </div>
      </div>
    </div>
    <div class="el-tree-node__content el-tree-header" v-if="filesList.length">
      <div style="width: 100%; margin-left: 5px;" class="row">
        <div class="col-6 custom-actions">
          <button
            @click="loadParentFolder"
            class="btn btn-link text-white"
            :disabled="isProcessing(currentFolder)"
          >
            <i class="fa fa-arrow-up"></i>
            <i v-if="isProcessing(currentFolder)" class="fas fa-spinner fa-spin"></i>
          </button>
          {{ $t("file-browser.goto-folder") }}:
          <input
            type="text"
            v-model="currentFolder"
            class="switches"
            style="border: 1px groove;"
            @keyup.enter="gotoFolder()"
            :disabled="isProcessing(currentFolder)"
          />
          <i v-if="isProcessing(currentFolder)" class="fas fa-spinner fa-spin"></i>
        </div>
      </div>
    </div>
    <el-tree
      :data="filesList"
      :props="defaultProps"
      :highlight-current="true"
      empty-text="Fetching..."
      @node-click="loadSubFolder"
      @node-expand="loadSubFolder"
    >
      <div class="row custom-tree-node" slot-scope="{ node, data }" style="width: 100%">
        <div class="col-12 custom-actions">
          <table style="width: 100%; table-layout:fixed;" class="table-responsive-sm">
            <tr>
              <td style="width: 50%;">
                <span>
                  <i :class="getFileIcon(data)"></i> {{ node.label }}
                  <i v-if="isProcessing(data.path)" class="fas fa-spinner fa-spin"></i>
                </span>
              </td>
              <td style="width: 18%; font-size: 70%" class="small">
                <template v-if="!hideDates">{{ data.creation_time }}</template>
              </td>
              <td style="width: 18%; font-size: 70%" class="small">
                <template v-if="!hideDates">{{ data.last_access }}</template>
              </td>
              <td style="width: 20%; font-size: 70%" class="small">{{ data.modified }}</td>
              <td style="width: 10%;" class="small">
                <div class="pull-right">{{ data.size }}</div>
              </td>
              <td style="width: 14%;" class="small">
                <div class="pull-right">{{ getPerms(data.perms) }}</div>
              </td>
              <td style="width: 20%;" class="small">
                <div class="pull-right">
                  <template v-if="data.file">
                    <base-button
                      type="info"
                      class="btn-link btn-info file-action-button"
                      @click="edit(data)"
                      v-tooltip="$t('tooltip.edit')"
                      v-if="getPerm(data.perms, 'write') === '1' && !hideRemove"
                    >
                      <i class="fas fa-edit"></i>
                    </base-button>
                    <base-button
                      type="info"
                      class="btn-link btn-primary file-action-button"
                      @click="download(data)"
                      v-tooltip="$t('tooltip.download')"
                      v-if="getPerm(data.perms, 'read') === '1'"
                    >
                      <i class="fas fa-download"></i>
                    </base-button>
                  </template>
                  <template v-else>
                    <base-button
                      type="info"
                      class="btn-link btn-info file-action-button"
                      @click="makeDir(data)"
                      v-tooltip="$t('tooltip.make-dir')"
                      v-if="getPerm(data.perms, 'write') === '1' && !hideRemove"
                    >
                      <i class="fas fa-folder-plus"></i>
                    </base-button>
                    <base-button
                      type="info"
                      class="btn-link btn-info file-action-button"
                      @click="uploadFile(data)"
                      v-tooltip="$t('tooltip.upload')"
                      v-if="getPerm(data.perms, 'write') === '1' && !hideUpload"
                    >
                      <i class="fas fa-upload"></i>
                    </base-button>
                  </template>
                  <base-button
                    type="danger"
                    class="btn-link btn-danger file-action-button"
                    @click="removeFile(data)"
                    v-tooltip="$t('tooltip.remove')"
                    v-if="!hideRemove"
                  >
                    <i class="fas fa-times"></i>
                  </base-button>
                </div>
              </td>
            </tr>
          </table>
        </div>
      </div>
    </el-tree>
  </div>
</template>

<script>
import { mapMutations, mapState, mapActions } from "vuex";
import _ from "lodash";
import { dummyDirs } from "../plugins/c2/message-routes/misc/mixin";

export default {
  props: {
    module: {
      type: String,
      required: true
    },
    credentials: {
      type: String,
      required: true
    },
    startPoint: {
      type: String,
      required: true
    },
    hideDates: {
      type: Boolean,
      default: false
    },
    hideRemove: {
      type: Boolean,
      default: false
    },
    hideUpload: {
      type: Boolean,
      default: false
    },
    uuid: {
      type: String,
      default: null
    }
  },
  data() {
    return {
      defaultProps: {
        children: "children",
        label: "name"
      },
      cmOptions: {
        theme: "base16-dark",
        lineNumbers: true,
        line: true,
        mode: "application/x-aspx"
      },
      currentFolder: this.startPoint
    };
  },
  computed: {
    filesList() {
      return this.rowFilesList[this.uniqueID] ? this.rowFilesList[this.uniqueID] : [];
    },
    uniqueID() {
      return this.uuid ? this.uuid : this.credentials;
    },
    ...mapState({
      rowFilesList(state) {
        return state[this.module].files;
      },
      processingPath(state) {
        return state[this.module].fileProcessingPath;
      },
      socketConnected: state => state.socket.SocketConnected
    })
  },
  methods: {
    isProcessing(path) {
      return this.$store.getters[`${this.module}/isProcessingPath`](path);
    },
    download(item) {
      this.$store.dispatch(`${this.module}/downloadFile`, {
        credentials: this.credentials,
        path: item.path
      });
    },
    edit(item) {
      this.clearEditing();
      this.$store.commit(`${this.module}/fileFetching`, true);
      this.$store.dispatch(`${this.module}/readFile`, {
        credentials: this.credentials,
        path: item.path
      });
      this.openModal({
        type: "editFile",
        data: { module: this.module, credentials: this.credentials }
      });
    },
    loadSubFolder(item, node) {
      if (!item.file) {
        if (item.children === dummyDirs) {
          // eslint-disable-next-line remove dummy folder content
          item.children = [];

          this.$store.commit(`${this.module}/addProcessingPath`, item.path);
          this.$store.dispatch(`${this.module}/fileBrowser`, {
            credentials: this.credentials,
            startPoint: _.trimEnd(item.path, "/")
          });
          setTimeout(() => {
            // eslint-disable-next-line
            node.expanded = true;
          }, 500);
        }
      }
    },
    loadParentFolder() {
      this.currentFolder = `../${this.currentFolder}`;
      this.$store.commit(`${this.module}/addProcessingPath`, this.currentFolder);
      this.$store.dispatch(`${this.module}/fileBrowser`, {
        credentials: this.credentials,
        startPoint: this.currentFolder
      });
    },
    getPerms(item) {
      if (Array.isArray(item)) {
        return (
          (item[0].read === "1" ? "r" : "") +
          (item[0].write === "1" ? "w" : "") +
          (item[0].execute === "1" ? "x" : "")
        );
      }
      return item;
    },
    getPerm(item, type) {
      if (Array.isArray(item)) {
        return item[0][type];
      }
      return "1"; // todo return for -rwxr-xr-x user.group.all
    },
    getFileIcon(item) {
      if (!item.file) {
        return "fas fa-folder";
      }
      switch (item.file) {
        case "aspx":
          return "fas fa-file-code";
        case "php":
          return "fas fa-file-code";
        case "zip":
          return "fas fa-file-archive";
        case "rar":
          return "fas fa-file-archive";
        case "tar.gz":
          return "fas fa-file-archive";
        case "xls":
          return "fas fa-file-excel";
        case "png":
          return "fas fa-file-image";
        case "jpg":
          return "fas fa-file-image";
        case "jpeg":
          return "fas fa-file-image";
        case "gif":
          return "fas fa-file-image";
        case "pdf":
          return "fas fa-file-pdf";
        default:
          return "fas fa-file-alt";
      }
    },
    makeDir(data) {
      this.openModal({
        type: "makeDir",
        data: { module: this.module, credentials: this.credentials, path: data.path }
      });
    },
    removeFile(data) {
      this.openModal({
        type: "confirmRemovingFile",
        data: {
          module: this.module,
          credentials: this.credentials,
          path: data.path,
          isPath: !data.file
        }
      });
    },
    uploadFile(data) {
      this.openModal({
        type: "uploadFileToDir",
        data: {
          module: this.module,
          credentials: this.credentials,
          path: data.path
        }
      });
    },
    gotoFolder() {
      this.$store.commit(`${this.module}/addProcessingPath`, this.currentFolder);
      this.$store.dispatch(`${this.module}/fileBrowser`, {
        credentials: this.credentials,
        startPoint: this.currentFolder
      });
    },
    ...mapActions({
      openModal: "openModal"
    }),
    ...mapMutations({
      clearEditing: "webShells/clearEditing"
    })
  },
  mounted() {
    if (!this.rowFilesList[this.uniqueID]) {
      this.$store.dispatch(`${this.module}/fileBrowser`, {
        credentials: this.credentials,
        startPoint: _.trimEnd(this.startPoint, "/")
      });
    }
  }
};
</script>

<style>
.el-tree {
  background: transparent;
  color: #b5bccf;
}

.el-tree-node:focus > .el-tree-node__content {
  background: transparent;
  color: #b5bccf;
}

.el-tree-node__content {
  margin-top: 10px;
  margin-bottom: 10px;
  height: 100%;
}

.el-tree--highlight-current .el-tree-node.is-current > .el-tree-node__content {
  background: #4f557b;
}
.is-expanded .custom-tree-node {
  margin-left: 2px;
  border-left: dotted;
  border-width: thin;
}
.custom-actions {
  padding-bottom: 15px;
}
.el-tree-node__content:hover {
  background-color: #3b4167;
}
.el-tree-node__content.el-tree-header:hover {
  background-color: inherit;
}
.el-tree-node__content.el-tree-header {
  cursor: default;
}
.el-tree-node__content > .el-tree-node__expand-icon {
  margin-bottom: 12px;
}
</style>
<style scoped>
.file-action-button {
  padding-bottom: 15px;
  padding-top: 0;
}
</style>
