<template>
  <div class="panel" :class="{ 'panel-expand': expand }" v-if="!remove">
    <div class="panel-heading">
      <slot name="header"></slot>
      <div class="row">
        <div class="col-lg-8">
          <h4 class="panel-title ml-2">
            {{ title }}
          </h4>
        </div>
        <div class="col-lg-4">
          <div class="pull-right">
            <button class="btn btn-link btn-icon text-white panel-button" @click="panelExpand">
              <i class="fa fa-expand" v-if="!expand"></i>
              <i class="fas fa-compress-arrows-alt" v-if="expand"></i>
            </button>
            <button class="btn btn-link btn-icon text-white panel-button" @click="panelCollapse">
              <i class="fas fa-window-minimize" v-if="!collapse"></i>
              <i class="far fa-window-maximize" v-if="collapse"></i>
            </button>
            <button class="btn btn-link btn-icon text-white panel-button" @click="panelRemove">
              <i class="fa fa-times"></i>
            </button>
          </div>
        </div>
      </div>
    </div>
    <slot name="beforeBody"></slot>
    <div class="panel-body" v-show="!collapse">
      <slot></slot>
    </div>
  </div>
</template>

<script>
export default {
  name: "Panel",
  props: ["title"],
  data() {
    return {
      expand: false,
      collapse: false,
      remove: false
    };
  },
  methods: {
    panelExpand() {
      this.expand = !this.expand;
    },
    panelCollapse() {
      this.collapse = !this.collapse;
      if (this.collapse) {
        this.expand = false;
      }
    },
    panelRemove() {
      this.remove = !this.remove;
    }
  }
};
</script>
