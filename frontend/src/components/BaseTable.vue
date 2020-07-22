<template>
  <table class="table tablesorter" :class="tableClass">
    <thead :class="theadClasses">
      <tr>
        <slot name="columns">
          <template v-if="mobile">
            <th v-for="column in mobileColumns" :key="column">
              <div style="display: flex">
                <span class="mr-1">{{ name(column) }}</span>
                <button
                  :class="{ 'text-white': isActiveSorting(column, 'asc') }"
                  class="btn btn-link sort-caret-top"
                  @click="setOrder(column, 'asc')"
                >
                  <i class="fa fa-sort-up"></i>
                </button>
                <button
                  :class="{ 'text-white': isActiveSorting(column, 'desc') }"
                  class="btn btn-link sort-caret-bottom"
                  @click="setOrder(column, 'desc')"
                >
                  <i class="fa fa-sort-down"></i>
                </button>
              </div>
            </th>
          </template>
          <template v-else>
            <th v-for="column in columns" :key="column">
              <div style="display: flex">
                <span class="mr-1">{{ name(column) }}</span>
                <button
                  :class="{ 'text-white': isActiveSorting(column, 'asc') }"
                  class="btn btn-link sort-caret-top"
                  @click="setOrder(column, 'asc')"
                >
                  <i class="fa fa-sort-up"></i>
                </button>
                <button
                  :class="{ 'text-white': isActiveSorting(column, 'desc') }"
                  class="btn btn-link sort-caret-bottom"
                  @click="setOrder(column, 'desc')"
                >
                  <i class="fa fa-sort-down"></i>
                </button>
              </div>
            </th>
          </template>
        </slot>
        <th v-if="showActions && !mobile" class="action_field">{{ $t("table.Actions") }}</th>
      </tr>
    </thead>
    <tbody :class="tbodyClasses">
      <template v-for="(item, index) in orderedData">
        <tr @click="openDetails(index)" :key="index">
          <slot :row="item">
            <template v-if="mobile">
              <td v-for="(column, index) in mobileColumns" :key="index">
                <template v-if="hasValue(item, column)">
                  {{ itemValue(item, column) }}
                </template>
              </td>
            </template>
            <template v-else>
              <td v-for="(column, index) in columns" :key="index">
                <template v-if="hasValue(item, column)">
                  {{ itemValue(item, column) }}
                </template>
              </td>
            </template>
          </slot>
          <slot name="actions" v-if="showActions && !mobile">
            <td class="action_field">
              <div class="row">
                <button
                  v-if="actions.interact"
                  class="btn btn-link text-success"
                  @click="interact(item)"
                  :disabled="!socketConnected"
                  v-tooltip="actionTooltips.interact"
                >
                  <i :class="actionIcons.interact"></i>
                </button>
                <button
                  v-if="actions.edit"
                  class="btn btn-link text-info"
                  @click="edit(item)"
                  :disabled="!socketConnected"
                  v-tooltip="actionTooltips.edit"
                >
                  <i :class="actionIcons.edit"></i>
                </button>
                <button
                  v-if="actions.delete"
                  class="btn btn-link text-danger"
                  @click="kill(item)"
                  :disabled="!socketConnected"
                  v-tooltip="actionTooltips.delete"
                >
                  <i :class="actionIcons.delete"></i>
                </button>
              </div>
            </td>
          </slot>
        </tr>
        <tr v-if="mobile" v-show="showDetails === index" :key="'m' + index">
          <td :colspan="mobileColumns.length">
            <table class="table-full-width table-responsive-sm table-responsive-md">
              <thead>
                <tr>
                  <th v-for="column in extendedColumns" :key="column">{{ name(column) }}</th>
                  <th>&nbsp;</th>
                </tr>
              </thead>
              <tr>
                <td v-for="(column, index) in extendedColumns" :key="index">
                  <template v-if="hasValue(item, column)">
                    {{ itemValue(item, column) }}
                  </template>
                </td>
                <td v-if="showActions">
                  <div class="row">
                    <button
                      v-if="actions.interact"
                      class="btn btn-link text-success"
                      @click="interact(item)"
                      :disabled="!socketConnected"
                      v-tooltip="actionTooltips.interact"
                    >
                      <i :class="actionIcons.interact"></i>
                    </button>
                    <button
                      v-if="actions.edit"
                      class="btn btn-link text-info"
                      @click="edit(item)"
                      :disabled="!socketConnected"
                      v-tooltip="actionTooltips.edit"
                    >
                      <i :class="actionIcons.edit"></i>
                    </button>
                    <button
                      v-if="actions.delete"
                      class="btn btn-link text-danger"
                      @click="kill(item)"
                      :disabled="!socketConnected"
                      v-tooltip="actionTooltips.delete"
                    >
                      <i :class="actionIcons.delete"></i>
                    </button>
                  </div>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </template>
    </tbody>
  </table>
</template>
<script>
import { mapState } from "vuex";
import _ from "lodash";
import i18n from "../i18n";

export default {
  name: "base-table",
  props: {
    columns: {
      type: Array,
      default: () => [],
      description: "Table columns"
    },
    data: {
      type: Array,
      default: () => [],
      description: "Table data"
    },
    type: {
      type: String, // striped | hover
      default: "",
      description: "Whether table is striped or hover type"
    },
    theadClasses: {
      type: String,
      default: "",
      description: "<thead> css classes"
    },
    tbodyClasses: {
      type: String,
      default: "",
      description: "<tbody> css classes"
    },
    showActions: {
      type: Boolean,
      default: false
    },
    actions: {
      type: Object,
      default: () => {
        return { edit: false, delete: false, interact: false };
      }
    },
    actionIcons: {
      type: Object,
      default: () => {
        return { edit: "fas fa-pencil-alt", delete: "fas fa-skull", interact: "fas fa-terminal" };
      }
    },
    actionTooltips: {
      type: Object,
      default: () => {
        return {
          edit: i18n.tc("tooltip.edit"),
          delete: i18n.tc("tooltip.kill"),
          interact: i18n.tc("tooltip.interact")
        };
      }
    },
    mobileColumns: {
      type: Array,
      default: () => []
    }
  },
  data() {
    return {
      showDetails: null,
      orderBy: this.columns[0],
      orderByDirection: "asc"
    };
  },
  computed: {
    orderedData() {
      return _.orderBy(this.data, [this.orderBy], [this.orderByDirection]);
    },
    tableClass() {
      return this.type && `table-${this.type}`;
    },
    extendedColumns() {
      return this.columns.filter(x => !this.mobileColumns.includes(x));
    },
    mobile() {
      return window.matchMedia("screen and (max-width: 700px)").matches;
    },
    ...mapState({
      socketConnected: state => state.socket.SocketConnected
    })
  },
  methods: {
    hasValue(item, column) {
      return item[column.toLowerCase()] !== "undefined";
    },
    itemValue(item, column) {
      return item[column];
    },
    interact(item) {
      this.$emit("interact", item);
    },
    edit(item) {
      this.$emit("edit", item);
    },
    kill(item) {
      this.$emit("kill", item);
    },
    name(name) {
      return this.$t(`table.${_.toLower(name)}`);
    },
    openDetails(index) {
      this.showDetails = this.showDetails === index ? null : index;
    },
    setOrder(column, direction) {
      this.orderBy = column;
      this.orderByDirection = direction;
    },
    isActiveSorting(column, direction) {
      return this.orderBy === column && this.orderByDirection === direction;
    }
  }
};
</script>
<style scoped>
.action_field {
  max-width: 6vw;
  width: 10%;
}
</style>
