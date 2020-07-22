export function saveAsFile(content, filename, type) {
  var a = document.createElement('a');
  var blob = new Blob([content], {"type": type});
  a.href = window.URL.createObjectURL(blob);
  a.download = filename;
  a.click();
}

export function download(url) {
  window.open(url);
}

export const dummyDirs = [
  {
    name: "Fetching...",
    file: "Fetching..."
  }
];

export function prepareForFileBrowser(Data) {
  let files = [];
  if (Data.Files) {
    files = Data.Files.map(item => {
      return {
        name: item.Filename,
        size: item.Filesize,
        modified: item.LastWrite,
        last_access: item.LastAccess,
        creation_time: item.CreationTime,
        perms: item.FilePerms,
        file: item.Filename.split(".").pop(),
        path: Data.CWD + item.Filename
      };
    });
  }
  let directories = [];
  if (Data.Directories) {
    directories = Data.Directories.map(item => {
      return {
        name: item.DirectoryName,
        size: null,
        modified: item.LastWrite,
        last_access: item.LastAccess,
        creation_time: item.CreationTime,
        perms: item.Perms,
        path: item.DirectoryName.slice(-1) === "/" ?
          Data.CWD + item.DirectoryName :
          Data.CWD + item.DirectoryName + "/",
        children: dummyDirs
      };
    });
  }
  return [...directories, ...files];
}

export default {
  saveAsFile,
  download,
  prepareForFileBrowser,
  dummyDirs
}
