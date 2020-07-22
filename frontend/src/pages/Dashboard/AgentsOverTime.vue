<template>
  <div>
    <div v-if="initialized" v-bind="cardAttributes" class="justify-center">
      <apexchart v-bind="chartAttributes" />
    </div>
  </div>
</template>

<script>
import Apexchart from "vue-apexcharts";
import { mapActions, mapState } from "vuex";
import { optionsLine } from "./chartOptions"; // import generic barchart settings

export default {
  components: {
    Apexchart
  },
  created() {
    if (!this.initialized) {
      console.warn("Fetching Graph Data... ");
      this.getAgentTimeline();
    }
  },
  computed: {
    ...mapState({
      initialized: state => state.metrics.AgentTimeLine.initialized,
      metricData: state => state.metrics.AgentTimeLine.data
    }),
    cardAttributes() {
      return {
        color: "#262D47"
      };
    },
    chartAttributes() {
      const options = {
        ...optionsLine,
        xaxis: this.xaxis(),
        // yaxis: this.yaxis(),
        stroke: {
          curve: "smooth",
          width: "5"
        },
        noData: {
          text: "No Data. Get pwning."
        }
      };
      return {
        height: "220px",
        options,
        series: this.series()
      };
    }
  },
  methods: {
    xaxis() {
      return {
        type: "datetime",
        labels: {
          style: {
            colors: ["#fff"]
          }
        }
      };
    },
    // yaxis() {
    //   const yaxis = [{
    //     title: {
    //       text: '# of Agents',
    //     },
    //     labels: {
    //       align: 'left',
    //     },
    //     oppostie: true,
    //   }];
    //   return yaxis;
    // },
    series() {
      // construct time series
      const arr = [];
      this.metricData.forEach((value, key) => {
        arr.push([value, key + 1]);
      });

      // adding a final plot point 5 minutes in the future to make the graph pretty
      const currentCount = arr[arr.length - 1][1];
      const d = new Date();
      d.setMinutes(d.getMinutes() + 5);
      arr.push([d.toString(), currentCount]);

      const series = [
        {
          name: "Agent Count Over Time",
          data: arr
        }
      ];
      console.log("series = ", series);
      return series;
    },
    ...mapActions({
      getAgentTimeline: "metrics/getAgentTimeline"
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
<style>
.apexcharts-xaxis-label {
  fill: #fff;
}
</style>
