<template>
  <div>
    <div class="row">
      <div class="col-12">
        <card type="chart" title="Game Over">
          <div class="p-3 text-white-50">
            <p>
              You are going to stop the server. We will make archive that you can use to restore the
              server whenever you need it but it will be stored on the server. If you want a backup
              now please select backup first!
            </p>
            <div class="row">
              <div class="col-lg-12">
                <base-button type="success" @click="makeBackup" class="mt-3">
                  Backup Now
                </base-button>

                <base-button type="danger" @click="endGame" class="mt-3" :disabled="!ready">
                  End Game
                </base-button>
              </div>
            </div>
          </div>
        </card>
      </div>
    </div>
  </div>
</template>
<script>
import { mapActions, mapState, mapMutations } from "vuex";

export default {
  computed: {
    ...mapState({
      ready: state => state.dust.dustReady
    })
  },
  methods: {
    endGame() {
      this.startDust(true);
      this.doEndGame();
    },
    ...mapActions({
      makeBackup: "admin/downloadBackup",
      doEndGame: "admin/endGame"
    }),
    ...mapMutations({
      markPageAsReadyForDust: "markPageAsReadyForDust",
      startDust: "startDust"
    })
  },
  mounted() {
    this.markPageAsReadyForDust(true);
  }
};
</script>
