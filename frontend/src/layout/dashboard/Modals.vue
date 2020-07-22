<template>
  <modal
    :show="showModal"
    :centered="false"
    :show-close="true"
    @keyup.esc.native="closeModal"
    @close="closeModal"
    modalClasses="base-modal"
  >
    <span slot="header">{{ getHeader() }}</span>

    <AddWebShell v-if="modalType === 'addWebShell'" />
    <GenerateWebShell v-if="modalType === 'generateWebShell'" />

    <ConfirmKillingListener :listener="modalData" v-if="modalType === 'confirmKillingListener'" />
    <AddListener v-if="modalType === 'addListener'" />
    <EditListener :listener="modalData" v-if="modalType === 'editListener'" />
    <GenerateAgent v-if="modalType === 'generateAgent'" :listener="modalData" />

    <ConfirmLogout v-if="modalType === 'confirmLogout'" :module="modalData" />

    <EditFile v-if="modalType === 'editFile'" :config="modalData" />
    <MakeDir v-if="modalType === 'makeDir'" :config="modalData" />
    <ConfirmRemovingFile v-if="modalType === 'confirmRemovingFile'" :config="modalData" />
    <UploadFileToDir v-if="modalType === 'uploadFileToDir'" :config="modalData" />

    <AddLootPassword v-if="modalType === 'addLootPassword'" />
    <AddLoot v-if="modalType === 'addLoot'" />

    <AddUser v-if="modalType === 'addUser'" />
    <DeleteUser v-if="modalType === 'deleteUser'" :user="modalData" />
    <EditUser v-if="modalType === 'editUser'" :user="modalData" />
    <UserSettings v-if="modalType === 'userSettings'" />

    <EditAgent v-if="modalType === 'editAgent'" :agent="modalData" />
  </modal>
</template>

<script>
import { mapActions, mapState } from "vuex";
import Modal from "../../components/Modal";
import AddWebShell from "../../pages/Modals/webshells/AddWebShell";
import GenerateWebShell from "../../pages/Modals/webshells/GenerateWebShell";
import ConfirmKillingListener from "../../pages/Modals/listeners/ConfirmKillingListener";
import AddListener from "../../pages/Modals/listeners/AddListener";
import EditListener from "../../pages/Modals/listeners/EditListener";
import ConfirmLogout from "../../pages/Modals/ConfirmLogout";
import EditFile from "../../pages/Modals/filesBrowser/EditFile";
import AddLootPassword from "../../pages/Modals/loot/AddLootPassword";
import AddLoot from "../../pages/Modals/loot/AddLoot";
import MakeDir from "../../pages/Modals/filesBrowser/MakeDir";
import ConfirmRemovingFile from "../../pages/Modals/filesBrowser/ConfirmRemovingFile";
import UploadFileToDir from "../../pages/Modals/filesBrowser/UploadFileToDir";
import AddUser from "../../pages/Modals/users/AddUser";
import DeleteUser from "../../pages/Modals/users/DeleteUser";
import EditUser from "../../pages/Modals/users/EditUser";
import UserSettings from "../../pages/Modals/users/UserSettings";
import GenerateAgent from "../../pages/Modals/listeners/GenerateAgent";
import EditAgent from "../../pages/Modals/agents/EditAgent";

export default {
  name: "Modals",
  components: {
    Modal,
    AddWebShell,
    GenerateWebShell,
    ConfirmKillingListener,
    AddListener,
    EditListener,
    ConfirmLogout,
    EditFile,
    MakeDir,
    ConfirmRemovingFile,
    UploadFileToDir,
    AddLootPassword,
    AddLoot,
    AddUser,
    DeleteUser,
    EditUser,
    GenerateAgent,
    UserSettings,
    EditAgent
  },
  computed: {
    ...mapState({
      showModal: state => state.modal.show,
      modalType: state => state.modal.type,
      modalData: state => state.modal.data
    })
  },
  methods: {
    getHeader() {
      switch (this.modalType) {
        case "addWebShell":
          return this.$t("modals.newWebShellSettings");
        case "generateWebShell":
          return this.$t("modals.generateWebShell");
        case "confirmKillingListener":
          return this.$t("modals.confirmKillingListener");
        case "addListener":
          return this.$t("modals.newListenerSettings");
        case "editListener":
          return this.$t("modals.editListener");
        case "confirmLogout":
          return this.$t("modals.logout-confirm-message");
        case "editFile":
          return this.$t("modals.editFile");
        case "makeDir":
          return this.$t("modals.create-new-folder");
        case "confirmRemovingFile":
          return this.$t("modals.remove-file");
        case "uploadFileToDir":
          return this.$t("modals.upload-file");
        case "addLootPassword":
          return this.$t("modals.add-loot-password");
        case "addLoot":
          return this.$t("modals.add-loot-manually");
        case "addUser":
          return this.$t("modals.add-user");
        case "deleteUser":
          return this.$t("modals.delete-user");
        case "editUser":
          return this.$t("modals.edit-user") + this.modalData.username;
        case "userSettings":
          return this.$t("modals.change-mfa");
        case "generateAgent":
          return this.$t("agents.generate_agent");
        case "editAgent":
          return this.$t("agents.edit-agent");
        default:
          return "";
      }
    },
    ...mapActions({
      closeModal: "closeModal"
    })
  }
};
</script>
