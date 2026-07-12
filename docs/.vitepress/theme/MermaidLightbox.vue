<script setup lang="ts">
import { onMounted, onUnmounted, ref, watch, nextTick } from "vue";
import { useRoute } from "vitepress";

// Several diagrams on this site are wide flowcharts that VitePress scales down to fit the
// prose column, which leaves the node labels smaller than the body text around them. This
// makes any rendered mermaid diagram clickable: click it and the SVG opens in an overlay
// where it can be zoomed and panned. The diagram itself is a vector, so it stays sharp at
// any magnification — the only thing missing was a way to actually magnify it.

const MIN_SCALE = 0.4;
const MAX_SCALE = 8;

const open = ref(false);
const svg = ref("");
const scale = ref(1);
const tx = ref(0);
const ty = ref(0);

const viewport = ref<HTMLElement | null>(null);
let dragging = false;
let dragStartX = 0;
let dragStartY = 0;

const route = useRoute();

function reset() {
  scale.value = 1;
  tx.value = 0;
  ty.value = 0;
}

function openDiagram(el: HTMLElement) {
  const node = el.querySelector("svg");
  if (!node) return;
  // Clone rather than move: the original has to stay in the page. Mermaid sizes its SVG with
  // an inline max-width that would otherwise cap the zoom at the prose column's width.
  const clone = node.cloneNode(true) as SVGElement;
  clone.removeAttribute("width");
  clone.removeAttribute("height");
  clone.style.maxWidth = "none";
  clone.style.width = "100%";
  // Height must stay derived from the viewBox. Forcing it to 100% makes the <svg> box as tall as
  // the stage while preserveAspectRatio letterboxes the actual drawing inside it — which both
  // creates the dead space above and below and makes the diagram's measured height useless for
  // fitting it to the viewport.
  clone.style.height = "auto";
  svg.value = clone.outerHTML;
  reset();
  open.value = true;
  nextTick(fitToViewport);
}

// Fitting to the stage's width alone isn't enough for these diagrams. Most of them are wide,
// short flowcharts, so width-fitting leaves the labels as small as they were in the page — the
// exact complaint this whole component exists to fix — with dead space above and below. Open at
// whatever zoom makes the diagram fill the viewport's *height* instead, and let the reader pan
// sideways. Clamped, because a very flat diagram would otherwise open at an absurd magnification.
function fitToViewport() {
  const stage = viewport.value?.querySelector(".mermaid-lightbox__stage");
  const box = viewport.value?.getBoundingClientRect();
  if (!stage || !box) return;
  const height = stage.getBoundingClientRect().height;
  if (!height) return;
  scale.value = Math.min(3, Math.max(1, (box.height * 0.85) / height));
}

function close() {
  open.value = false;
  svg.value = "";
}

function zoomBy(factor: number) {
  scale.value = Math.min(MAX_SCALE, Math.max(MIN_SCALE, scale.value * factor));
}

function onWheel(event: WheelEvent) {
  event.preventDefault();
  // Zoom toward the pointer rather than the centre, so zooming in on a specific node keeps
  // that node under the cursor instead of drifting off-screen.
  const box = viewport.value?.getBoundingClientRect();
  if (!box) return;
  const px = event.clientX - box.left - box.width / 2;
  const py = event.clientY - box.top - box.height / 2;
  const next = Math.min(
    MAX_SCALE,
    Math.max(MIN_SCALE, scale.value * (event.deltaY < 0 ? 1.12 : 1 / 1.12)),
  );
  const ratio = next / scale.value;
  tx.value = px - (px - tx.value) * ratio;
  ty.value = py - (py - ty.value) * ratio;
  scale.value = next;
}

function onPointerDown(event: PointerEvent) {
  dragging = true;
  dragStartX = event.clientX - tx.value;
  dragStartY = event.clientY - ty.value;
  (event.currentTarget as HTMLElement).setPointerCapture(event.pointerId);
}

function onPointerMove(event: PointerEvent) {
  if (!dragging) return;
  tx.value = event.clientX - dragStartX;
  ty.value = event.clientY - dragStartY;
}

function onPointerUp(event: PointerEvent) {
  dragging = false;
  (event.currentTarget as HTMLElement).releasePointerCapture(event.pointerId);
}

function onKeydown(event: KeyboardEvent) {
  if (!open.value) return;
  if (event.key === "Escape") close();
  if (event.key === "+" || event.key === "=") zoomBy(1.2);
  if (event.key === "-") zoomBy(1 / 1.2);
  if (event.key === "0") reset();
}

// Mermaid renders asynchronously, so the .mermaid containers may not hold an <svg> yet when
// the route first settles. A MutationObserver picks them up whenever they do land, which also
// covers client-side navigation between articles.
let observer: MutationObserver | null = null;

function attach() {
  const diagrams = document.querySelectorAll<HTMLElement>(".vp-doc .mermaid");
  diagrams.forEach((el) => {
    // The overlay's own stage carries .vp-doc (it has to, for the site's mermaid styling to
    // apply to the clone), so it matches this selector too. Without this guard it picks up the
    // click affordance and a click handler of its own — hover chrome on the zoomed diagram, and
    // a lightbox that reopens itself on top of itself.
    if (el.closest(".mermaid-lightbox")) return;
    if (el.dataset.zoomable === "true" || !el.querySelector("svg")) return;
    el.dataset.zoomable = "true";
    el.setAttribute("role", "button");
    el.setAttribute("tabindex", "0");
    el.setAttribute("aria-label", "Open diagram in a zoomable viewer");
    el.addEventListener("click", () => openDiagram(el));
    el.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        openDiagram(el);
      }
    });
  });
}

onMounted(() => {
  attach();
  observer = new MutationObserver(() => attach());
  observer.observe(document.body, { childList: true, subtree: true });
  window.addEventListener("keydown", onKeydown);
});

onUnmounted(() => {
  observer?.disconnect();
  window.removeEventListener("keydown", onKeydown);
});

watch(
  () => route.path,
  () => {
    close();
    nextTick(attach);
  },
);

// The body must not scroll behind the overlay while it's open.
watch(open, (isOpen) => {
  document.body.style.overflow = isOpen ? "hidden" : "";
});
</script>

<template>
  <Teleport to="body">
    <div
      v-if="open"
      class="mermaid-lightbox"
      role="dialog"
      aria-modal="true"
      aria-label="Diagram viewer"
      @click.self="close"
    >
      <div class="mermaid-lightbox__toolbar">
        <button type="button" aria-label="Zoom out" @click="zoomBy(1 / 1.2)">
          &minus;
        </button>
        <span class="mermaid-lightbox__level"
          >{{ Math.round(scale * 100) }}%</span
        >
        <button type="button" aria-label="Zoom in" @click="zoomBy(1.2)">
          +
        </button>
        <button type="button" class="mermaid-lightbox__text" @click="reset">
          Reset
        </button>
        <button
          type="button"
          class="mermaid-lightbox__text"
          aria-label="Close diagram viewer"
          @click="close"
        >
          Close
        </button>
      </div>

      <div
        ref="viewport"
        class="mermaid-lightbox__viewport"
        @wheel="onWheel"
        @pointerdown="onPointerDown"
        @pointermove="onPointerMove"
        @pointerup="onPointerUp"
        @pointercancel="onPointerUp"
        @click.self="close"
      >
        <!-- .mermaid nested *inside* .vp-doc, not alongside it: custom.css styles mermaid with
             descendant selectors (`.vp-doc .mermaid …`), including the line-height fix that stops
             multi-line node labels being clipped. Both classes on one element wouldn't match, and
             the labels would clip here exactly as they used to in the page. -->
        <div
          class="vp-doc mermaid-lightbox__stage"
          :style="{
            transform: `translate(${tx}px, ${ty}px) scale(${scale})`,
          }"
        >
          <div class="mermaid" v-html="svg" />
        </div>
      </div>

      <p class="mermaid-lightbox__hint">
        Scroll to zoom · drag to pan · <kbd>Esc</kbd> to close
      </p>
    </div>
  </Teleport>
</template>
