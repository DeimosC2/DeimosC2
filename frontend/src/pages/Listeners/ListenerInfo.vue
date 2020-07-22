<template>
  <card type="task" :title="$t('listeners.info')">
    <info-table :data="prettyListenerTable" :columns="columns"> </info-table>
  </card>
</template>

<script>
import _ from "lodash";

export default {
  props: {
    listener: Object
  },
  data() {
    return {
      columns: ["Name", "LType", "Host", "Key"]
    };
  },
  computed: {
    prettyListenerTable() {
      const prettyListener = _.clone(this.listener);
      prettyListener.Host = `${this.listener.Host}:${this.listener.Port}`;
      return prettyListener;
    }
  }
};
</script>
