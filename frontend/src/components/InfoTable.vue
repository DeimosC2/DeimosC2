<template>
  <table class="table tablesorter" :class="tableClass">
    <tbody :class="tbodyClasses">
      <template>
        <slot :row="data">
          <tr v-for="(column, index) in columns" :key="index">
            <td>{{ name(column) }}</td>
            <td>
              <template v-if="hasValue(data, column)">
                {{ itemValue(data, column) }}
              </template>
              <div
                class="pull-right"
                v-tooltip="'Edit'"
                @click="edit(column)"
                v-if="canBeEdit(column)"
              >
                <i class="fa fa-edit"></i>
              </div>
            </td>
          </tr>
        </slot>
      </template>
    </tbody>
  </table>
</template>
<script>
import _ from "lodash";

export default {
  name: "info-table",
  props: {
    columns: {
      type: Array,
      default: () => [],
      description: "Table columns"
    },
    data: {
      type: Object,
      default: () => {},
      description: "Table data"
    },
    editableColumns: {
      type: Array,
      default: () => [],
      description: "Table columns that has edit icon"
    },
    tbodyClasses: {
      type: String,
      default: "",
      description: "<tbody> css classes"
    }
  },
  computed: {
    tableClass() {
      return this.type && `table-${this.type}`;
    }
  },
  methods: {
    hasValue(item, column) {
      return item[column] !== "undefined";
    },
    itemValue(item, column) {
      return item[column];
    },
    name(name) {
      return this.$t(`table.${_.toLower(name)}`);
    },
    canBeEdit(column) {
      return this.editableColumns.includes(column);
    },
    edit(column) {
      this.$emit("edit", column);
    }
  }
};
</script>
