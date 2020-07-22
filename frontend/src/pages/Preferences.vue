<template>
  <div>
    <div class="row">
      <div class="col-md-12">
        <card type="task" :title="$t('users.preferences')">
          <div class="card-body">
            <span class="text-white">{{ $t("users.ui-color") }}</span>
            <div class="row">
              <div class="col-md-12">
                <input type="radio" value="red" v-model="skin" id="red" @change="updateTheme()" />
                <label for="red" style="color: red; padding-left: 10px;"> Red </label>
              </div>
            </div>
            <div class="row">
              <div class="col-md-12">
                <input
                  type="radio"
                  value="green"
                  v-model="skin"
                  id="green"
                  @change="updateTheme()"
                />
                <label for="green" style="color: green; padding-left: 10px;"> Green </label>
              </div>
            </div>
            <br />
            <span class="mt-5 text-white">{{ $t("users.language") }}</span>
            <div class="row">
              <div class="col-md-12">
                <select @change="updateLocale" v-model="lang" class="form-control">
                  <option v-for="item in langs" :value="item" :key="item">
                    {{ item }}
                  </option>
                </select>
              </div>
            </div>
          </div>
        </card>
      </div>
    </div>
  </div>
</template>
<script>
import { mapState } from "vuex";

export default {
  data() {
    return {
      skin: "red",
      lang: "en"
    };
  },
  computed: {
    ...mapState({
      langs: "langs"
    })
  },
  methods: {
    updateTheme() {
      localStorage.setItem("skin_theme", this.skin);
      window.location.reload();
    },
    updateLocale() {
      localStorage.setItem("lang", this.lang);
      this.$root.$i18n.locale = this.lang;
    }
  },
  mounted() {
    this.skin = localStorage.getItem("skin_theme");
    this.lang = localStorage.getItem("lang");
  }
};
</script>
<style></style>
