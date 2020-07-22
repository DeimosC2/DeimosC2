<template>
  <div v-if="initialized" v-bind="cardAttributes">
    <apexchart v-bind="chartAttributes" />
  </div>
</template>

<script>
import Apexchart from "vue-apexcharts";
import { mapState, mapGetters, mapActions } from "vuex";
import { optionsCircle } from "./chartOptions"; // import generic barchart settings

export default {
  components: {
    Apexchart
  },
  created() {
    if (!this.initialized) {
      console.warn("Fetching Graph Data... ");
      this.getAgentByListener();
    }
  },
  computed: {
    ...mapState({
      debug: "debug",
      initialized: state => state.metrics.AgentByListener.initialized,
      metricData: state => state.metrics.AgentByListener.data,
      listenerData: state => state.listeners.listeners
    }),
    ...mapGetters({
      getListenerByKey: "listeners/getListenerByKey",
      AgentsByListenerSeries: "metrics/AgentsByListenerSeries"
    }),
    cardAttributes() {
      return {
        color: "#262D47"
      };
    },
    chartAttributes() {
      const options = {
        ...optionsCircle,
        labels: this.labels(),
        legend: {
          labels: {
            useSeriesColors: true
          },
          show: true,
          position: "bottom",
          offsetX: 0,
          offsetY: 0,
          formatter: (val, opts) => {
            const { series } = opts.w.globals;
            const sum = series.reduce((a, b) => a + b, 0);
            const value = opts.w.globals.series[opts.seriesIndex];
            const percentage = Math.round((value / sum) * 100);
            return `${val} - ${percentage}%`;
          }
        },
        noData: {
          text: "No Data. Get pwning."
        }
      };
      return {
        series: this.series(),
        options
      };
    }
  },
  methods: {
    labels() {
      // returns the Listener Names as an array
      const labels = [];

      // maps LISTENERS to METRICS Data
      this.listenerData.forEach(listener => {
        labels.push(listener.Name);
      });
      return labels;
    },
    series() {
      // returns array of the values for each label
      const arr = [];
      this.$logging(
        `AgentsByListener::methods:series:metricData = ${JSON.stringify(this.metricData)}`,
        this.debug
      );
      this.listenerData.forEach(listener => {
        this.$logging(
          `AgentsByListener::methods:series:forEarch:listener = ${JSON.stringify(listener)}`,
          this.debug
        );
        this.$logging(
          `AgentsByListener::methods:series:forEarch:metricData[listener.key] = ${
            this.metricData[listener.key]
          }`,
          this.debug
        );
        arr.push(this.metricData[listener.Key]);
      });
      this.$logging(`AgentsByListener::methods:series:arr = ${arr.toString()}`, this.debug);
      return arr;
    },
    ...mapActions({
      getAgentByListener: "metrics/getAgentByListener"
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
