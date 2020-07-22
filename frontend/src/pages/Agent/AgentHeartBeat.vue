<template>
  <card type="task" :title="$t('agents.heart-beat-title')">
    <apexchart type="line" :options="chartOptions" :series="chartData" height="80px"></apexchart>
  </card>
</template>

<script>
import Apexchart from "vue-apexcharts";

export default {
  props: {
    agent: {
      Type: Object,
      Required: true
    }
  },
  components: {
    Apexchart
  },
  data() {
    return {
      value: new Array(300).fill(0)
    };
  },
  computed: {
    chartData() {
      return [
        {
          name: "series-1",
          data: this.value
        }
      ];
    },
    chartOptions() {
      return {
        chart: {
          id: "hear-beat",
          zoom: {
            enabled: false
          },
          sparkline: {
            enabled: true
          }
        },
        stroke: {
          show: true,
          curve: "smooth",
          lineCap: "round",
          colors: ["rgb(255, 35, 40)"],
          width: 1
        },
        xaxis: {
          labels: {
            show: false
          },
          max: 300,
          min: 0
        },
        yaxis: {
          show: false,
          min: 0,
          max: 0.5
        },
        tooltip: {
          enabled: false
        },
        legend: {
          show: false
        },
        grid: {
          show: false
        }
      };
    }
  },
  mounted() {
    // setInterval(() => { this.value.shift(); this.value.push(1); }, 5000);
    setInterval(() => {
      this.value.shift();
      this.value.push(0);
    }, 500);

    // eslint-disable-next-line
      this.$store.subscribe((mutation, state) => {
      if (mutation.type === "agents/heartBeat" && mutation.payload.AgentKey === this.agent.Key) {
        // this.$logging(`mutation.payload=${JSON.stringify(mutation.payload)}`, this.debug);
        this.value.shift();
        this.value.push(1);
      }
    });
  }
};
</script>
