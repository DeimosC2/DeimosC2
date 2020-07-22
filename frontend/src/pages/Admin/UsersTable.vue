<template>
  <div>
    <ConfirmAction
      :show-modal="showModal"
      @confirmed="resetUserPassword"
      @cancel="cancelAction"
      :question="$t('confirm-reset-password')"
    />
    <card type="task">
      <div class="row" slot="header">
        <div class="col-lg-4 col-4">
          <h4 class="card-title">{{ $t("users.users") }}</h4>
        </div>
        <div class="col-lg-8 col-8">
          <div class="pull-right">
            <base-button type="primary" class="mr-3 action-button" @click="addUser">
              {{ $t("users.add-user") }}
            </base-button>
            <base-button type="success" class="mr-3 action-button" @click="updateUserSettings">
              {{ $t("users.settings") }}
            </base-button>
          </div>
        </div>
      </div>
      <base-table
        class="table-responsive-sm table-responsive-md"
        :data="users"
        :columns="headers"
        :showActions="true"
        :actions="{ edit: true, delete: true, interact: true }"
        @edit="editUser"
        @kill="deleteUser"
        @interact="confirmResetUser"
        thead-classes="text-primary"
        :actionIcons="{
          edit: 'fas fa-pencil-alt',
          delete: 'fas fa-skull',
          interact: 'fas fa-redo'
        }"
        :actionTooltips="{
          edit: $t('tooltip.edit'),
          delete: $t('tooltip.delete'),
          interact: $t('tooltip.reset-password')
        }"
        :mobileColumns="mobileHeaders"
        style="table-layout:fixed;"
      >
      </base-table>
    </card>
  </div>
</template>

<script>
import { mapActions, mapState } from "vuex";
import ConfirmAction from "../Modals/ConfirmAction";

export default {
  name: "UsersTable",
  components: {
    ConfirmAction
  },
  data() {
    return {
      headers: ["id", "username", "lastLogin", "failedAttempts", "isAdmin"],
      mobileHeaders: ["id", "username", "isAdmin"],
      showModal: false,
      currentUser: null
    };
  },
  computed: {
    ...mapState({
      users: state => state.admin.users
    })
  },
  methods: {
    addUser() {
      this.openModal({ type: "addUser", data: {} });
    },
    editUser(user) {
      this.openModal({ type: "editUser", data: user });
    },
    deleteUser(user) {
      this.openModal({ type: "deleteUser", data: user });
    },
    updateUserSettings() {
      this.openModal({ type: "userSettings" });
    },
    confirmResetUser(user) {
      this.currentUser = user;
      this.showModal = true;
    },
    resetUserPassword() {
      this.resetUser(this.currentUser.id);
    },
    cancelAction() {
      this.currentUser = null;
      this.showModal = false;
    },
    ...mapActions({
      fetchUserList: "admin/fetchUserList",
      resetUser: "admin/resetUser",
      openModal: "openModal"
    })
  },
  mounted() {
    this.fetchUserList();
  }
};
</script>
