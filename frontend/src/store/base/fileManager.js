import Vue from "vue";

function findPath(files, path) {
  let found = files.find(item => {
    return item.path === path;
  });
  if (found) {
    return found;
  }
  for (let i = 0; i < files.length; i += 1) {
    if (files[i].children) {
      found = findPath(files[i].children, path);
      if (found) {
        return found;
      }
    }
  }
  return false;
}

class FileManager {
  constructor() {
    this.state = {
      files: {},
      editingFilePath: null,
      editingFileContent: null,
      fileSaving: false,
      fileSaveResult: "",
      fileFetching: false,
      fileProcessingPath: [],
      startPoint: "./"
    };

    this.mutations = {
      setFiles(state, _var) {
        if (!state.files[_var.uuid]) {
          Vue.set(state.files, _var.uuid, _var.files);
        } else if (_var.parent.slice(-2) === "./") {
          // top folder
          Vue.set(state.files, _var.uuid, _var.files);
        } else {
          const found = findPath(state.files[_var.uuid], _var.parent);
          if (found) {
            Vue.set(found, "children", _var.files);
          } else {
            // make it new parent
            Vue.set(state.files, _var.uuid, _var.files);
          }
        }
      },

      setStartPoint(state, _var) {
        state.startPoint = _var;
      },

      editingFilePath(state, path) {
        state.editingFilePath = path;
      },

      editFile(state, content) {
        state.editingFileContent = content;
      },

      clearEditing(state) {
        state.editingFilePath = null;
        state.editingFileContent = null;
      },

      fileFetching(state, status) {
        state.fileFetching = status;
      },

      fileSaving(state, status) {
        state.fileSaving = status;
      },

      fileSaveResult(state, result) {
        state.fileSaveResult = result;
      },

      startSavingFile(state) {
        state.fileSaveResult = "";
        state.fileSaving = true;
      },

      addProcessingPath(state, path) {
        state.fileProcessingPath.push(path);
      },

      removeProcessingPath(state, path) {
        const index = state.fileProcessingPath.findIndex(item => item === path);
        if (index >= 0) {
          state.fileProcessingPath.splice(index, 1);
        }
      },

      clearCache(state) {
        state.files = {};
        state.fileProcessingPath = [];
      }
    };

    this.getters = {
      isProcessingPath: state => path => {
        const index = state.fileProcessingPath.findIndex(item => item === path);
        return index >= 0;
      }
    };
  }
}

export default FileManager;
