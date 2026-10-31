<script setup lang="ts">
// The /checks index: every check Bulwark runs, grouped the way the app groups findings, with a
// filter box. Data is the same catalog.json the per-check pages render from.
import { computed, ref } from "vue";
import catalog from "../../checks/catalog.json";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const query = ref("");

const groups = computed(() => {
  const q = query.value.trim().toLowerCase();
  return catalog.groups
    .map((g) => ({
      ...g,
      checks: catalog.checks
        .filter((c) => c.group === g.id)
        .filter(
          (c) =>
            !q ||
            c.title.toLowerCase().includes(q) ||
            c.id.toLowerCase().includes(q) ||
            c.explain.toLowerCase().includes(q),
        )
        .sort(
          (a, b) =>
            SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
            a.id.localeCompare(b.id),
        ),
    }))
    .filter((g) => g.checks.length);
});
const shown = computed(() => groups.value.reduce((n, g) => n + g.checks.length, 0));
const label = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
const plain = (t: string) => t.replace(/\{\{\s*\w+\.(\w+)\s*\}\}/g, (_, f) => `‹${f.replace(/_/g, " ")}›`);
</script>

<template>
  <div class="bw-checks">
    <input
      v-model="query"
      class="bw-checks-filter"
      type="search"
      placeholder="Filter checks: ssh, docker, mcp, BLWK-CRED…"
      aria-label="Filter checks"
    />
    <p class="bw-checks-count">{{ shown }} of {{ catalog.checks.length }} checks</p>
    <section v-for="g in groups" :key="g.id" class="bw-checks-group">
      <h2 :id="g.id">{{ g.title }} <span class="bw-checks-n">{{ g.checks.length }}</span></h2>
      <p class="bw-checks-blurb">{{ g.blurb }}</p>
      <ul>
        <li v-for="c in g.checks" :key="c.id">
          <a :href="`/checks/${c.slug}`">
            <span :class="`bw-sev bw-sev-${c.severity}`">{{ label(c.severity) }}</span>
            <span class="bw-checks-title">{{ plain(c.title) }}</span>
            <code>{{ c.id }}</code>
          </a>
        </li>
      </ul>
    </section>
  </div>
</template>
