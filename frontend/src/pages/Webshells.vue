<template>
  <div>
    <ConfirmAction
      :show-modal="showModal"
      @confirmed="killWebshell"
      @cancel="cancelAction"
      :question="$t('confirm-killing-webshell')"
    />
    <div class="row">
      <div class="col-12">
        <card>
          <div class="row" slot="header">
            <div class="col-lg-4 col-12">
              <h4 class="card-title">{{ $t("sidebar.webshells") }}</h4>
            </div>
            <div class="col-lg-8 col-12">
              <div class="pull-right">
                <base-button type="primary" class="mr-3 action-button" @click="addShell">
                  {{ $t("webshell.add-webshell") }}
                </base-button>
                <base-button type="success" @click="generateWebShell" class="action-button">
                  {{ $t("webshell.generate") }}
                </base-button>
              </div>
            </div>
          </div>
          <base-table
            class="table-responsive-sm"
            :data="webShells"
            :columns="headers"
            :showActions="true"
            :actions="{ edit: true, delete: true, interact: true }"
            :actionIcons="{
              edit: 'fas fa-folder',
              delete: 'fas fa-skull',
              interact: 'fas fa-terminal'
            }"
            @edit="gotoWebshellFolder"
            @interact="gotoWebshellInterface"
            @kill="confirmKillingWebshell"
            thead-classes="text-primary"
            :mobileColumns="mobileHeaders"
            style="table-layout:fixed;"
          >
          </base-table>
        </card>
      </div>
    </div>
  </div>
</template>
<script>
import { mapState, mapActions } from "vuex";
import ConfirmAction from "./Modals/ConfirmAction";

export default {
  components: {
    ConfirmAction
  },
  data() {
    return {
      headers: ["UUID", "URL", "OS", "Username"],
      mobileHeaders: ["UUID", "URL"],
      showModal: false,
      currentItem: null
    };
  },
  computed: mapState({
    webShells: state => state.webShells.webShells
  }),
  methods: {
    gotoWebshellFolder(item) {
      const { UUID } = item;
      this.$router.push(`/webshells/${UUID}/files`);
    },
    gotoWebshellInterface(item) {
      const { UUID } = item;
      this.$router.push(`/webshells/${UUID}`);
    },
    killWebshell() {
      this.deleteWebShell(this.currentItem);
    },
    addShell() {
      this.openModal({ type: "addWebShell", data: {} });
    },
    generateWebShell() {
      this.openModal({ type: "generateWebShell", data: {} });
    },
    cancelAction() {
      this.currentItem = null;
      this.showModal = false;
    },
    confirmKillingWebshell(item) {
      this.currentItem = item;
      this.showModal = true;
    },
    ...mapActions({
      deleteWebShell: "webShells/deleteWebShell",
      openModal: "openModal"
    })
  }
};
</script>
