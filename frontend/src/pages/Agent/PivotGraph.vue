<template>
  <div style="height: 80vh">
    <div class="pull-right">
      <button @click="zoomIn" class="btn btn-link btn-success">
        <i class="fas fa-search-plus"></i>
      </button>
      <button @click="zoom" class="btn btn-link btn-success">
        <i class="fas fa-search-minus"></i>
      </button>
    </div>
    <div id="tree-simple"></div>
  </div>
</template>

<script>
import { mapActions, mapState } from "vuex";
import { Treant } from "treant-js";
import jQuery from "jquery";
import "treant-js/Treant.css";
import Panzoom from "@panzoom/panzoom";

window.Raphael = require("raphael");

const $ = jQuery;

export default {
  props: {
    listener: {
      default: null
    }
  },
  data() {
    return {
      config: {
        chart: {
          container: "#tree-simple",
          rootOrientation: "WEST",
          hideRootNode: true,
          nodeAlign: "TOP",
          levelSeparation: 60,
          siblingSeparation: 60,
          subTeeSeparation: 60,
          connectors: {
            type: "curve",
            style: {
              stroke: "#b5bccf"
            }
          },
          node: {
            HTMLclass: "nodeExample"
          }
        },
        nodeStructure: {},
        panzoom: null
      }
    };
  },
  created() {
    if (!this.initialized) {
      console.warn("Fetching Pivot Graph Data... ");
      this.getPivotGraph(this.listener);
    }
  },
  computed: {
    ...mapState({
      initialized: state => state.metrics.PivotGraph.initialized,
      pivotGraph: state => state.metrics.PivotGraph.data
    })
  },
  watch: {
    initialized(newValue) {
      if (newValue) {
        this.drawPivotGraph();
      }
    }
  },
  methods: {
    drawPivotGraph() {
      this.config.nodeStructure = this.pivotGraph;
      // eslint-disable-next-line
      new Treant(this.config, () => {
          const div = document.getElementById("tree-simple");
          const height = div.getElementsByTagName("svg")[0].height.baseVal.value;
          const width = div.getElementsByTagName("svg")[0].width.baseVal.value;

          div.style.height = `${height}px`;
          div.style.width = `${width}px`;

          const elem = document.getElementById("tree-simple");
          this.panzoom = Panzoom(elem, {
            maxScale: 10,
            origin: "top left"
          });
          const vh = window.innerHeight * 0.8;
          this.panzoom.zoom(vh / height.toFixed(2) - 0.1, { animate: true });
        },
        $
      );
    },
    zoom() {
      this.panzoom.zoomOut();
    },
    zoomIn() {
      this.panzoom.zoomIn();
    },
    ...mapActions({
      getPivotGraph: "metrics/getPivotGraph"
    })
  },
  mounted() {
    if (this.initialized) {
      this.drawPivotGraph();
    }
  }
};
</script>
<style>
#tree-simple {
  height: 400px;
  margin: 5px;
  width: 100%;
}
.nodeExample {
  background-color: #31354d;
  color: #b5bccf;
  -webkit-box-shadow: 0 5px 35px 2px rgba(225, 78, 202, 0.175);
  box-shadow: 0 5px 35px 2px rgba(225, 78, 202, 0.175);
  border-color: #b5bccf;
  border-style: solid;
  border-width: 1px;
}
.nodeExample p {
  padding: 5px 15px;
  color: #b5bccf;
}
.nodeExample img {
  margin: 5px;
  margin-right: 10px;
}

.pivot-agent-link {
  color: #fff;
  width: 150px;
  word-break: break-all;
}
</style>
