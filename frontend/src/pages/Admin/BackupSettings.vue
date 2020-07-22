<template>
  <card type="task" :title="$t('settings.backup-settings')">
    <div class="row">
      <div class="col-lg-4">
        <div class="text-white">
          {{ $t("settings.time") }}
        </div>
        <div class="row">
          <div class="col-lg-3 offset-lg-2">
            <button
              class="btn btn-default form-control"
              :disabled="hours >= 23"
              @click="increaseHours()"
            >
              <i class="fa fa-plus"></i>
            </button>
          </div>
          <div class="col-lg-3 offset-lg-1">
            <button
              class="btn btn-default form-control"
              :disabled="minutes >= 59"
              @click="increaseMinutes()"
            >
              <i class="fa fa-plus"></i>
            </button>
          </div>
        </div>
        <div class="row">
          <div class="col-lg-3 offset-lg-2">
            <input type="number" v-model="hours" class="form-control" @change="validateHours" />
          </div>
          <div class="col-lg-1">:</div>
          <div class="col-lg-3">
            <input type="number" v-model="minutes" class="form-control" @change="validateMinutes" />
          </div>
        </div>
        <div class="row">
          <div class="col-lg-3 offset-lg-2">
            <button
              class="btn btn-default form-control"
              :disabled="hours <= 0"
              @click="decreaseHours()"
            >
              <i class="fa fa-minus"></i>
            </button>
          </div>
          <div class="col-lg-3 offset-lg-1">
            <button
              class="btn btn-default form-control"
              :disabled="minutes === 0"
              @click="decreaseMinutes()"
            >
              <i class="fa fa-minus"></i>
            </button>
          </div>
        </div>
      </div>
      <div class="col-lg-8">
        <div class="text-white">
          {{ $t("settings.days") }}
        </div>
        <div class="row">
          <div class="col-lg-12">
            <label class="pr-3 py-2" v-for="day in week" :key="day.key">
              <input :value="day.key" type="checkbox" v-model="daysOfWeek" />
              {{ day.name }}
            </label>
          </div>
          <div class="col-lg-12">
            <base-alert type="default">{{ formatBackupInfo() }}</base-alert>
          </div>
          <div class="col-lg-6">
            <base-button type="primary" @click="saveSettings" class="form-control">
              {{ $t("buttons.save") }}
            </base-button>
          </div>
          <div class="col-lg-6">
            <base-button type="success" @click="downloadBackup" class="form-control">
              Backup Now
            </base-button>
          </div>
        </div>
      </div>
    </div>
  </card>
</template>

<script>
import { mapActions, mapState } from "vuex";

export default {
  data() {
    return {
      week: [
        { key: "Monday", name: this.$t("week.Monday") },
        { key: "Tuesday", name: this.$t("week.Tuesday") },
        { key: "Wednesday", name: this.$t("week.Wednesday") },
        { key: "Thursday", name: this.$t("week.Thursday") },
        { key: "Friday", name: this.$t("week.Friday") },
        { key: "Saturday", name: this.$t("week.Saturday") },
        { key: "Sunday", name: this.$t("week.Sunday") }
      ],
      daysOfWeek: [],
      hours: 23,
      minutes: 59
    };
  },
  computed: {
    ...mapState({
      rowDaysOfWeek: state => state.admin.backupSettings.days,
      rowHours: state => state.admin.backupSettings.hours,
      rowMinutes: state => state.admin.backupSettings.minutes
    })
  },
  watch: {
    rowDaysOfWeek() {
      this.daysOfWeek = this.rowDaysOfWeek;
    },
    rowHours() {
      this.hours = this.rowHours;
    },
    rowMinutes() {
      this.minutes = this.rowMinutes;
    }
  },
  methods: {
    validateHours() {
      this.hours = `0${this.hours}`.slice(-2);
      this.hours = this.hours > 23 ? 23 : this.hours;
      this.hours = this.hours < 0 ? 0 : this.hours;
    },
    validateMinutes() {
      this.minutes = `0${this.minutes}`.slice(-2);
      this.minutes = this.minutes > 59 ? 59 : this.minutes;
      this.minutes = this.minutes < 0 ? 0 : this.minutes;
    },
    increaseHours() {
      this.hours += 1;
      this.hours = `0${this.hours}`.slice(-2);
    },
    decreaseHours() {
      // eslint-disable-next-line
      this.hours = `0${--this.hours}`.slice(-2);
    },
    increaseMinutes() {
      this.minutes += 1;
      this.minutes = `0${this.minutes}`.slice(-2);
    },
    decreaseMinutes() {
      // eslint-disable-next-line
      this.minutes = `0${--this.minutes}`.slice(-2);
    },
    saveSettings() {
      const status = !!this.daysOfWeek.length;
      this.updateBackupSchedule({
        Status: status,
        Hour: `${this.hours}:${this.minutes}`,
        Days: this.daysOfWeek
      });
    },
    formatBackupInfo() {
      return this.daysOfWeek.length
        ? `${this.$t("settings.make-backup-every")} ${this.daysOfWeek
            .map(item => {
              return this.$t(`week.${item}`);
            })
            .join(", ")} ${this.$t("settings.at")} ${`0${this.hours}`.slice(
            -2
          )}:${`0${this.minutes}`.slice(-2)}`
        : this.$t("settings.dont-make-backups");
    },
    ...mapActions({
      listBackupSchedule: "admin/listBackupSchedule",
      updateBackupSchedule: "admin/updateBackupSchedule",
      downloadBackup: "admin/downloadBackup"
    })
  },
  mounted() {
    this.listBackupSchedule();
    this.daysOfWeek = this.rowDaysOfWeek;
    this.hours = this.rowHours;
    this.minutes = this.rowMinutes;
  }
};
</script>
