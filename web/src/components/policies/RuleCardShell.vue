<script setup lang="ts">
import type { MergeStrategy, OsFamily } from '@/api'
import MergeStrategyBadge from '@/components/common/MergeStrategyBadge.vue'
import OsBadges from '@/components/common/OsBadges.vue'
import { useI18n } from '@/i18n'

defineProps<{
  title: string
  description: string
  enabled: boolean
  platforms: OsFamily[]
  mergeStrategy: MergeStrategy
}>()

const emit = defineEmits<{
  (e: 'update:enabled', value: boolean): void
  (e: 'update:platforms', value: OsFamily[]): void
  (e: 'update:mergeStrategy', value: MergeStrategy): void
}>()

const { t } = useI18n()
</script>

<template>
  <section
    class="rounded-lg border transition-colors"
    :class="enabled ? 'border-blue-200 bg-white shadow-sm' : 'border-slate-200 bg-slate-50/60'"
  >
    <div class="flex flex-wrap items-start justify-between gap-4 p-4">
      <div class="max-w-2xl">
        <div class="flex flex-wrap items-center gap-2">
          <h3 class="text-sm font-semibold text-slate-900">{{ title }}</h3>
          <MergeStrategyBadge
            v-if="enabled"
            :strategy="mergeStrategy"
            editable
            @update:strategy="emit('update:mergeStrategy', $event)"
          />
          <MergeStrategyBadge v-else :strategy="mergeStrategy" short />
        </div>
        <p class="mt-1 text-xs text-slate-600">{{ description }}</p>
      </div>

      <label class="inline-flex cursor-pointer items-center gap-2.5 select-none">
        <input
          type="checkbox"
          class="h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-600"
          :checked="enabled"
          @change="emit('update:enabled', ($event.target as HTMLInputElement).checked)"
        />
        <span class="text-xs font-semibold" :class="enabled ? 'text-blue-700' : 'text-slate-600'">
          {{ t.policies.ruleActive }}
        </span>
      </label>
    </div>

    <template v-if="enabled">
      <div class="flex flex-wrap items-center gap-2 border-t border-slate-100 bg-slate-50/70 px-4 py-2.5">
        <span class="text-xs font-medium text-slate-600">{{ t.policies.platformsLabel }}</span>
        <OsBadges
          :platforms="platforms"
          editable
          compact
          @update:platforms="emit('update:platforms', $event)"
        />
      </div>

      <div class="border-t border-slate-200 p-4">
        <slot />
      </div>
    </template>

    <div v-else class="border-t border-slate-200/70 px-4 py-2.5 text-xs text-slate-500">
      {{ t.policies.ruleInactiveHint }}
    </div>
  </section>
</template>
