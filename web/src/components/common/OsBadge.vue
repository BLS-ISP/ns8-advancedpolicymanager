<script setup lang="ts">
import type { OsFamily } from '@/api'

const props = defineProps<{
  os: OsFamily
  compact?: boolean
}>()

const labels: Record<OsFamily, string> = {
  WINDOWS: 'Windows',
  LINUX: 'Linux',
  MACOS: 'macOS'
}

const styles: Record<OsFamily, string> = {
  WINDOWS: 'bg-sky-50 text-sky-800 border-sky-200',
  LINUX: 'bg-amber-50 text-amber-900 border-amber-200',
  MACOS: 'bg-slate-100 text-slate-800 border-slate-300'
}
</script>

<template>
  <span
    class="inline-flex items-center gap-1.5 rounded border font-medium leading-none"
    :class="[styles[props.os], props.compact ? 'px-1.5 py-0.5 text-[11px]' : 'px-2 py-1 text-xs']"
  >
    <!-- Windows 4-pane grid icon -->
    <svg
      v-if="props.os === 'WINDOWS'"
      class="h-3 w-3 shrink-0"
      viewBox="0 0 16 16"
      fill="currentColor"
      aria-hidden="true"
    >
      <path d="M1.5 2.5h5.75v5.75H1.5V2.5zm7.25 0h5.75v5.75H8.75V2.5zM1.5 9.75h5.75v5.75H1.5V9.75zm7.25 0h5.75v5.75H8.75V9.75z" />
    </svg>
    <!-- Linux terminal prompt icon -->
    <svg
      v-else-if="props.os === 'LINUX'"
      class="h-3 w-3 shrink-0"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      stroke-width="1.75"
      aria-hidden="true"
    >
      <rect x="1.5" y="2.5" width="13" height="11" rx="1.5" />
      <path stroke-linecap="round" stroke-linejoin="round" d="M4.5 6l2.5 2-2.5 2M8.5 10h3" />
    </svg>
    <!-- macOS command key icon -->
    <svg
      v-else
      class="h-3 w-3 shrink-0"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      stroke-width="1.6"
      aria-hidden="true"
    >
      <path
        stroke-linecap="round"
        stroke-linejoin="round"
        d="M5.5 5.5V3.75a1.75 1.75 0 1 0-1.75 1.75H5.5zm0 0h5m-5 0v5m5-5V3.75a1.75 1.75 0 1 1 1.75 1.75H10.5zm0 0v5m0 0h1.75a1.75 1.75 0 1 1-1.75 1.75V10.5zm0 0h-5m0 0v1.75a1.75 1.75 0 1 1-1.75-1.75H5.5z"
      />
    </svg>
    <span>{{ labels[props.os] }}</span>
  </span>
</template>
