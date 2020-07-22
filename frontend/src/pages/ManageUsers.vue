<template>
  <div>
    <div class="row">
      <div class="col-md-12">
        <UsersTable v-if="initialized" />
      </div>
    </div>
  </div>
</template>
<script>
import { mapActions, mapState } from "vuex";
import UsersTable from "./Admin/UsersTable";

export default {
  components: {
    UsersTable
  },
  data() {
    return {};
  },
  computed: {
    ...mapState({
      initialized: state => state.agents.initialized
    })
  },
  methods: {
    addUser() {
      this.doAddUser({ login: "mytestuser", password: "mypassword" });
    },
    ...mapActions({
      doAddUser: "admin/addUser",
      fetchUserList: "admin/fetchUserList"
    })
  }
};
</script>
<style></style>
