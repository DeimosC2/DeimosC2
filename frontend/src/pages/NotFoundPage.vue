<template>
  <div class="wrapper">
    <div class="main-panel">
      <div class="content">
        <fade-transition :duration="100" mode="out-in">
          <card type="login" style="width: 20rem;" class="col-lg-4 offset-lg-3">
            <img slot="image" class="card-img-top" src="/img/login-logo.png" alt="DeimosC2 Logo" />
            <h4 class="card-title">404 This page does not exist</h4>
            <router-link :to="{ path: '/' }" class="text-white">Go Home > </router-link>
          </card>
        </fade-transition>
      </div>
    </div>
  </div>
</template>

<script>
export default {};
</script>
