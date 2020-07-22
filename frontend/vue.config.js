// eslint-disable-next-line import/no-extraneous-dependencies
const webpack = require("webpack");
const path = require("path");

const apiServer = process.env.VUE_APP_APISERVER;

module.exports = {
  lintOnSave: false,
  configureWebpack: {
    // Set up all the aliases we use in our app.
    devtool: "source-map",
    resolve: {
      alias: {
        "chart.js": "chart.js/dist/Chart.js",
        "@C2": path.join(__dirname, "./src/")
      },
      extensions: [".js", ".json", ".jsx"]
    },
    devServer: {
      https: false,
      proxy: {
        // websocket proxy to dev server
        "/ws": { target: apiServer },

        // proxy colls for user auth
        "/log.in": { target: apiServer },
        "/log.out": { target: apiServer },
        "/change.pass": { target: apiServer },
        "/set.up": { target: apiServer },
        "/token": { target: apiServer },

        // proxy calls for downloading files
        "/generated": { target: apiServer },
        "/looted": { target: apiServer }
      }
    },
    plugins: [
      new webpack.optimize.LimitChunkCountPlugin({
        maxChunks: 6
      })
    ]
  },
  pwa: {
    name: "Deimos C2",
    themeColor: "#344675",
    msTileColor: "#344675",
    appleMobileWebAppCapable: "yes",
    appleMobileWebAppStatusBarStyle: "#344675"
  },
  pluginOptions: {
    i18n: {
      locale: "en",
      fallbackLocale: "en",
      localeDir: "locales",
      enableInSFC: false
    }
  },
  css: {
    sourceMap: process.env.NODE_ENV !== "production"
  }
};
