// Layouts
import DashboardLayout from "@/layout/dashboard/DashboardLayout.vue";
import LoginPageLayout from "@/layout/login/LoginPageLayout.vue";

// GeneralViews
import NotFound from "@/pages/NotFoundPage.vue";

import {
  ifAgentExists,
  guard,
  isAuthorized,
  ifWebshellExists,
  ifListenerExists,
  isAdmin
} from "./guards";

// Unauthorized Pages
const Login = () => import(/* webpackChunkName: "unauthorized" */ "@/pages/LoginPage.vue");
const ChangePassword = () =>
  import(/* webpackChunkName: "unauthorized" */ "@/pages/ChangePassword.vue");
const SetUp = () => import(/* webpackChunkName: "unauthorized" */ "@/pages/SetUpPage.vue");
const MFA = () => import(/* webpackChunkName: "unauthorized" */ "@/pages/MFA.vue");

// Admin pages
const Dashboard = () => import(/* webpackChunkName: "admin" */ "@/pages/Dashboard.vue");
const Admin = () => import(/* webpackChunkName: "admin" */ "@/pages/Admin.vue");
const ManageUsers = () => import(/* webpackChunkName: "admin" */ "@/pages/ManageUsers.vue");
const Agents = () => import(/* webpackChunkName: "admin" */ "@/pages/Agents.vue");
const AgentInterface = () => import(/* webpackChunkName: "admin" */ "@/pages/AgentInterface.vue");
const Webshells = () => import(/* webpackChunkName: "admin" */ "@/pages/Webshells.vue");
const WebShellsInterface = () =>
  import(/* webpackChunkName: "admin" */ "@/pages/WebShellsInterface.vue");
const WebShellsFiles = () => import(/* webpackChunkName: "admin" */ "@/pages/WebShellsFiles.vue");
const Listeners = () => import(/* webpackChunkName: "admin" */ "@/pages/Listeners.vue");
const ListenerInterface = () =>
  import(/* webpackChunkName: "admin" */ "@/pages/ListenerInterface.vue");
const Loot = () => import(/* webpackChunkName: "admin" */ "@/pages/Loot.vue");
const Preferences = () => import(/* webpackChunkName: "admin" */ "@/pages/Preferences.vue");
const EndGame = () => import(/* webpackChunkName: "admin" */ "@/pages/EndGame.vue");

const routes = [
  {
    path: "/login",
    beforeEnter: isAuthorized,
    component: LoginPageLayout,
    children: [
      {
        path: "/",
        name: "login",
        component: Login
      },
      {
        path: "/setup",
        name: "setup",
        component: SetUp
      }
    ]
  },
  {
    path: "/password-change",
    name: "changePassword",
    component: LoginPageLayout,
    children: [
      {
        path: "/password-change",
        name: "changePassword",
        component: ChangePassword
      },
      {
        path: "/mfa",
        name: "mfa",
        component: MFA
      }
    ]
  },
  {
    path: "/",
    component: DashboardLayout,
    beforeEnter: guard,
    redirect: "/dashboard",
    children: [
      {
        path: "dashboard",
        name: "dashboard",
        component: Dashboard
      },
      {
        path: "/admin",
        name: "admin",
        component: Admin,
        beforeEnter: isAdmin
      },
      {
        path: "/users",
        name: "users",
        component: ManageUsers,
        beforeEnter: isAdmin
      },
      {
        path: "/preferences",
        name: "preferences",
        component: Preferences
      },
      {
        path: "/agents",
        name: "agents",
        component: Agents
      },
      {
        path: "/agents/:agentUUID",
        name: "agentInterface",
        component: AgentInterface,
        beforeEnter: ifAgentExists
      },
      {
        path: "/webshells",
        name: "webshells",
        component: Webshells
      },
      {
        path: "/webshells/:shellUUID",
        name: "webshellsInterface",
        beforeEnter: ifWebshellExists,
        component: WebShellsInterface
      },
      {
        path: "/webshells/:shellUUID/files",
        name: "webshellsFileBrowser",
        beforeEnter: ifWebshellExists,
        component: WebShellsFiles
      },
      {
        path: "/listeners",
        name: "listeners",
        component: Listeners
      },
      {
        path: "/listeners/:listenerName",
        name: "listenerInterface",
        beforeEnter: ifListenerExists,
        component: ListenerInterface
      },
      {
        path: "/loot",
        name: "loot",
        component: Loot
      },
      {
        path: "/end-game",
        name: "end-game",
        component: EndGame,
        beforeEnter: isAdmin
      }
    ]
  },
  { path: "*", component: NotFound }
];

/**
 * Asynchronously load view (Webpack Lazy loading compatible)
 * The specified component must be inside the Views folder
 * @param  {string} name  the filename (basename) of the view to load.
function view(name) {
   var res= require('../components/Dashboard/Views/' + name + '.vue');
   return res;
};* */

export default routes;
