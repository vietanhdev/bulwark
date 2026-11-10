<script setup lang="ts">
import { ref } from "vue";
import { useData } from "vitepress";
const { isDark } = useData();
const views = [
  { id: "scan", label: "Scan", dark: "overview-dark.png", light: "overview.png", alt: "Scan with developer findings and the Fix now review action, using synthetic data", caption: "Run checks and review their findings in one place." },
  { id: "secrets", label: "Secrets", dark: "secrets-inventory.png", light: "secrets-inventory-light.png", alt: "Secrets with a searchable synthetic AWS profile list and expanded cache metadata", caption: "Understand profile references and cache timestamps. No secret values or authentication checks." },
  { id: "tools", label: "Tools", dark: "tools.png", light: "tools-light.png", alt: "Tools directory for configuration, remote hosts, file changes, malware scans, rules and history", caption: "Broader system capabilities remain available when you need them." },
] as const;
const active = ref(0);
function keys(event: KeyboardEvent) {
  if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
  event.preventDefault();
  active.value = event.key === "Home" ? 0 : event.key === "End" ? views.length - 1 : (active.value + (event.key === "ArrowRight" ? 1 : -1) + views.length) % views.length;
  document.getElementById(`gallery-${views[active.value].id}`)?.focus();
}
</script>
<template>
  <section class="product-gallery" aria-label="Developer workbench preview">
    <div class="gallery-tabs" role="tablist" aria-label="Workbench screenshots" @keydown="keys">
      <button v-for="(view, index) in views" :id="`gallery-${view.id}`" :key="view.id" role="tab" :aria-selected="active === index" :aria-controls="`gallery-panel-${view.id}`" :tabindex="active === index ? 0 : -1" @click="active = index">{{ view.label }}</button>
    </div>
    <figure v-for="(view, index) in views" v-show="active === index" :id="`gallery-panel-${view.id}`" :key="view.id" role="tabpanel" :aria-labelledby="`gallery-${view.id}`">
      <img :src="`/screenshots/${isDark ? view.dark : view.light}`" :alt="view.alt" width="1800" height="1320" />
      <figcaption>{{ view.caption }} Screenshots use synthetic fixtures.</figcaption>
    </figure>
  </section>
</template>
<style scoped>
.product-gallery { max-width:1040px; margin:16px auto 0; padding:0 24px; }
.gallery-tabs { display:flex; gap:8px; margin-bottom:12px; border-bottom:1px solid var(--vp-c-divider); }
.gallery-tabs button { padding:10px 16px; font-weight:600; color:var(--vp-c-text-2); border-bottom:2px solid transparent; }
.gallery-tabs button[aria-selected="true"] { border-color:var(--vp-c-brand-1); color:var(--vp-c-text-1); }
.gallery-tabs button:hover { background:var(--vp-c-bg-soft); }
.gallery-tabs button:focus-visible { outline:2px solid var(--vp-c-brand-1); outline-offset:-3px; border-radius:6px; }
figure { margin:0; }
img { width:100%; height:auto; border:1px solid var(--vp-c-divider); border-radius:9px; }
figcaption { margin-top:10px; font-size:13px; line-height:1.6; color:var(--vp-c-text-2); }
</style>
