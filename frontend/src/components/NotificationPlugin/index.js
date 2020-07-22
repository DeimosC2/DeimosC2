import Notifications from "./Notifications.vue";

const NotificationStore = {
  state: [], // here the notifications will be added
  settings: {
    overlap: false,
    verticalAlign: "bottom",
    horizontalAlign: "right",
    type: "info",
    timeout: 3000,
    closeOnClick: true,
    showClose: true
  },
  setOptions(options) {
    this.settings = Object.assign(this.settings, options);
  },
  removeNotification(timestamp) {
    const indexToDelete = this.state.findIndex(n => n.timestamp === timestamp);
    if (indexToDelete !== -1) {
      this.state.splice(indexToDelete, 1);
    }
  },
  addNotification(notification) {
    if (typeof notification === "string" || notification instanceof String) {
      // eslint-disable-next-line
      notification = { message: notification };
    }
    // eslint-disable-next-line
    notification.timestamp = new Date();
    notification.timestamp.setMilliseconds(
      notification.timestamp.getMilliseconds() + this.state.length
    );
    // eslint-disable-next-line
    notification = Object.assign({}, this.settings, notification);
    this.state.push(notification);
  },
  notify(notification) {
    if (Array.isArray(notification)) {
      notification.forEach(notificationInstance => {
        this.addNotification(notificationInstance);
      });
    } else {
      this.addNotification(notification);
    }
  }
};

const NotificationsPlugin = {
  install(Vue, options) {
    const app = new Vue({
      data: {
        notificationStore: NotificationStore
      },
      methods: {
        notify(notification) {
          this.notificationStore.notify(notification);
        }
      }
    });
    // eslint-disable-next-line
    Vue.prototype.$notify = app.notify;
    // eslint-disable-next-line
    Vue.prototype.$notifications = app.notificationStore;
    Vue.component("Notifications", Notifications);
    if (options) {
      NotificationStore.setOptions(options);
    }
  }
};

export default NotificationsPlugin;
