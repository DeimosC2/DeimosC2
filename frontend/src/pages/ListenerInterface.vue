<template>
  <div>
    <div class="row">
      <div class="col-lg-6 offset">
        <ListenerInfo v-if="initialized" :listener="listener" />
      </div>
      <div class="col-lg-6">
        <ListenerActions :listener="listener" />
      </div>
    </div>
    <div class="row">
      <div class="col-lg-12">
        <card type="task" :title="$t('listeners.graph')">
          <PivotGraph v-if="initialized" :listener="listener.Key" />
        </card>
      </div>
    </div>
  </div>
</template>

<script>
import { mapState, mapGetters, mapMutations } from "vuex";

import ListenerInfo from "./Listeners/ListenerInfo.vue";
import ListenerActions from "./Listeners/ListenerActions.vue";
import PivotGraph from "./Agent/PivotGraph";

export default {
  data() {
    return {
      listenerName: this.$route.params.listenerName
    };
  },
  computed: {
    ...mapState({
      initialized: state => state.agents.initialized
    }),
    ...mapGetters({
      getListenerByKey: "listeners/getListenerByKey"
    }),
    listener() {
      return this.getListenerByKey(this.listenerName);
    }
  },
  components: {
    ListenerInfo,
    ListenerActions,
    PivotGraph
  },
  methods: {
    ...mapMutations({
      destroyPivotGraph: "metrics/destroyPivotGraph"
    })
  },
  beforeRouteLeave(to, from, next) {
    this.destroyPivotGraph();
    next();
  }
};
</script>
