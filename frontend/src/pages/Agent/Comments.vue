<template>
  <div class="mt-3">
    <div
      v-for="(comment, index) in comments"
      :key="index"
      class="comment-block"
      :class="{ 'my-comment': isCurrentUser(comment) }"
    >
      <div class="text-white comment-name">
        {{ comment.User }}
      </div>
      <div
        :class="{
          'comment-arrow-left': !isCurrentUser(comment),
          'comment-arrow-right': isCurrentUser(comment)
        }"
      ></div>
      <div class="comment">
        <div
          class="form-text"
          :class="{ 'text-right': !isCurrentUser(comment), 'text-left': isCurrentUser(comment) }"
        >
          {{ comment.CreationTime | datetime }}
        </div>
        <hr />
        <div class="text-white">
          <pre>{{ comment.Comment }}</pre>
        </div>
      </div>
    </div>
    <div>
      <textarea
        :placeholder="$t('comment.placeholder')"
        v-model="comment"
        rows="10"
        class="form-control"
      ></textarea>
    </div>
    <div>
      <base-button type="success" :disabled="emptyComment()" @click="sendComment()">
        {{ $t("buttons.send") }}
      </base-button>
    </div>
  </div>
</template>

<script>
import { mapActions, mapState } from "vuex";
import _ from "lodash";

export default {
  name: "Comments",
  props: {
    agent: {
      Type: String,
      Required: true
    }
  },
  data() {
    return {
      comment: null
    };
  },
  computed: {
    comments() {
      return this.rowComments ? this.rowComments[this.agent] : [];
    },
    ...mapState({
      rowComments: state => state.agents.comments,
      currentUser: state => state.auth.userName
    })
  },
  methods: {
    isCurrentUser(comment) {
      return this.currentUser === comment.User;
    },
    emptyComment() {
      return !this.comment || _.trim(this.comment) === "";
    },
    sendComment() {
      this.doSendComment({ AgentKey: this.agent, Comment: this.comment });
      this.comment = null;
    },
    ...mapActions({
      fetchComments: "agents/fetchComments",
      doSendComment: "agents/sendComment"
    })
  },
  mounted() {
    this.fetchComments(this.agent);
  }
};
</script>
