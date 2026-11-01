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
      aria-label="Bulwark demo: run a scan, open a problem and its one-click fix, check a remote machine, and switch between light and dark themes"
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
  /* The frames are the window edge to edge; the rounding happens only here. clip-path as well as
     border-radius, because some engines don't clip a playing <video> to its radius. The hairline
     ring stands in for the window border so the edge reads on light and dark pages alike. */
  border-radius: 10px;
  clip-path: inset(0 round 10px);
  background: var(--vp-c-bg-soft);
  outline: 1px solid color-mix(in srgb, var(--vp-c-text-1) 12%, transparent);
  outline-offset: -1px;
  box-shadow: 0 30px 70px -24px rgba(15, 20, 25, 0.45);
}
:root.dark .hero-demo {
  box-shadow: 0 30px 70px -20px rgba(0, 0, 0, 0.7);
}
</style>
