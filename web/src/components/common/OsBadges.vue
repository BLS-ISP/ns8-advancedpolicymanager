<script setup lang="ts">
import { ALL_PLATFORMS, type OsFamily } from '@/api'
import OsBadge from './OsBadge.vue'

const props = defineProps<{
  platforms: OsFamily[]
  editable?: boolean
  compact?: boolean
  allowEmpty?: boolean
}>()

const emit = defineEmits<{
  (e: 'update:platforms', value: OsFamily[]): void
}>()

function togglePlatform(os: OsFamily) {
  const exists = props.platforms.includes(os)
  if (exists) {
    if (!props.allowEmpty && props.platforms.length <= 1) {
      return
    }
    emit(
      'update:platforms',
      props.platforms.filter((p) => p !== os)
    )
  } else {
    emit('update:platforms', [...props.platforms, os])
  }
}
</script>

<template>
  <div v-if="editable" class="inline-flex flex-wrap items-center gap-1.5" role="group">
    <button
      v-for="os in ALL_PLATFORMS"
      :key="os"
      type="button"
      :aria-pressed="platforms.includes(os)"
      class="rounded-md transition-opacity"
      :class="
        platforms.includes(os)
          ? 'ring-2 ring-blue-600 ring-offset-1 opacity-100'
          : 'opacity-45 hover:opacity-80'
      "
      @click="togglePlatform(os)"
    >
      <OsBadge :os="os" :compact="compact" />
    </button>
  </div>
  <div v-else class="inline-flex flex-wrap items-center gap-1">
    <OsBadge v-for="os in platforms" :key="os" :os="os" :compact="compact" />
  </div>
</template>
