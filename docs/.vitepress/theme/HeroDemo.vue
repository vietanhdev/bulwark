<script setup>
import { onMounted, ref } from "vue";

// Vue doesn't reliably set the `muted` *property* from the attribute, and browsers block autoplay
// on non-muted video — so set it imperatively on mount and kick off playback.
const v = ref(null);
onMounted(() => {
  const el = v.value;
  if (!el) return;
  el.muted = true;
  const p = el.play?.();
  if (p) p.catch(() => {});
});
</script>

<template>
  <div class="hero-demo-wrap">
    <video
      ref="v"
      class="hero-demo"
      src="/demo.mp4"
      autoplay
      muted
      loop
      playsinline
      preload="auto"
      poster="/screenshots/overview.png"
      aria-label="Bulwark demo: run a scan, read plain-language findings, catch a leaked API key in an AI assistant, and re-theme the app"
    ></video>
  </div>
</template>

<style scoped>
.hero-demo-wrap {
  max-width: 1040px;
  margin: 12px auto 0;
  padding: 0 24px;
}
.hero-demo {
  width: 100%;
  display: block;
  border-radius: 8px;
  background: #17121a;
  box-shadow: 0 30px 70px -24px rgba(20, 10, 20, 0.5);
}
:root.dark .hero-demo {
  box-shadow: 0 30px 70px -20px rgba(0, 0, 0, 0.7);
}
</style>
