<template>
  <div>
    <span class="fas fa-sync-alt fa-spin fa-2x" v-if="!initialized"></span>
    <div v-if="initialized" v-bind="cardAttributes" class="justify-center">
      <apexchart v-bind="chartAttributes" />
    </div>
  </div>
</template>

<script>
import Apexchart from "vue-apexcharts";
import { mapActions, mapState } from "vuex";
import { optionsColumn } from "./chartOptions"; // import generic barchart settings

export default {
  components: {
    Apexchart
  },
  created() {
    if (!this.initialized) {
      console.warn("Fetching Graph Data... ");
      this.getAgentByOSType();
    }
  },
  computed: {
    ...mapState({
      initialized: state => state.metrics.AgentOSType.initialized,
      metricData: state => state.metrics.AgentOSType.data
    }),
    cardAttributes() {
      return {
        color: "#262D47"
      };
    },
    chartAttributes() {
      const options = {
        ...optionsColumn,
        xaxis: this.xaxis(),
        noData: {
          text: "No Data. Get pwning."
        }
      };
      return {
        options,
        series: this.series()
      };
    }
  },
  methods: {
    filteredData() {
      const nonNull = {};
      Object.keys(this.metricData).forEach(OS => {
        if (this.metricData[OS] !== 0) nonNull[OS] = this.metricData[OS];
      });
      console.warn(`fliteredData = ${JSON.stringify(nonNull)}`);
      return nonNull;
    },
    xaxis() {
      return {
        categories: Object.keys(this.filteredData()),
        labels: {
          style: {
            colors: ["#fff"]
          }
        }
      };
    },
    series() {
      return [
        {
          name: "Agent Count",
          data: Object.values(this.filteredData())
        }
      ];
    },
    agentCount() {
      return Object.values(this.filteredData()).reduce((a, b) => a + b, 0);
    },
    ...mapActions({
      getAgentByOSType: "metrics/getAgentByOSType"
    })
  }
};
</script>
<style scoped>
/* .chart {
    background-color: #262D47;
    padding: 25px 25px;
    border-radius: 4px;
  } */
</style>
