<template>
  <div class="row">
    <div class="col-12">
      <card>
        <div class="row" slot="header">
          <div class="col-lg-4 col-4">
            <h4 class="card-title">{{ $t("sidebar.listeners") }}</h4>
          </div>
          <div class="col-lg-8 col-8">
            <div class="pull-right">
              <base-button
                type="primary"
                class="action-button"
                @click="addListener"
                :title="$t('listeners.addListener')"
              >
                {{ $t("listeners.addListener") }}
              </base-button>
            </div>
          </div>
        </div>
        <base-table
          class="table-responsive-sm"
          :data="listeners"
          :columns="headers"
          :showActions="true"
          :actions="{ edit: true, delete: true, interact: true }"
          @interact="gotoListenerInterface"
          @kill="killListener"
          @edit="openEditModal"
          thead-classes="text-primary"
          :mobileColumns="mobileHeaders"
          style="table-layout:fixed;"
        >
        </base-table>
      </card>
    </div>
  </div>
</template>

<script>
import { mapActions, mapState } from "vuex";

export default {
  data() {
    return {
      searchQuery: "",
      headers: ["Name", "LType", "Host", "Port"],
      mobileHeaders: ["Name", "LType", "Host"]
    };
  },
  computed: {
    ...mapState({
      listeners: state => state.listeners.listeners
    })
  },
  methods: {
    gotoListenerInterface(item) {
      this.$router.push(`/listeners/${item.Key}`);
    },
    killListener(item) {
      this.openModal({ type: "confirmKillingListener", data: item });
    },
    openEditModal(item) {
      this.openModal({ type: "editListener", data: item });
    },
    addListener() {
      this.openModal({ type: "addListener", data: {} });
    },
    ...mapActions({
      openModal: "openModal",
      listenersSettings: "listeners/getListenersSettings"
    })
  },
  mounted() {
    this.listenersSettings();
  }
};
</script>
