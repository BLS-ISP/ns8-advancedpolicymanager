<script setup lang="ts">
import { ArrowDownToLine, Layers } from 'lucide-vue-next'
import type { MergeStrategy } from '@/api'
import { useI18n } from '@/i18n'

const props = defineProps<{
  strategy: MergeStrategy
  editable?: boolean
  short?: boolean
}>()

const emit = defineEmits<{
  (e: 'update:strategy', value: MergeStrategy): void
}>()

const { t } = useI18n()
</script>

<template>
  <div v-if="editable" class="inline-flex items-center rounded-md border border-slate-200 bg-slate-50 p-0.5">
    <button
      type="button"
      class="inline-flex items-center gap-1 rounded px-2 py-1 text-xs font-medium transition-colors"
      :class="
        props.strategy === 'OVERRIDE'
          ? 'bg-white text-blue-700 shadow-sm ring-1 ring-slate-200'
          : 'text-slate-600 hover:text-slate-900'
      "
      @click="emit('update:strategy', 'OVERRIDE')"
    >
      <ArrowDownToLine class="h-3.5 w-3.5" aria-hidden="true" />
      <span>{{ t.merge.OVERRIDE_SHORT }}</span>
    </button>
    <button
      type="button"
      class="inline-flex items-center gap-1 rounded px-2 py-1 text-xs font-medium transition-colors"
      :class="
        props.strategy === 'APPEND_UNIQUE'
          ? 'bg-white text-emerald-700 shadow-sm ring-1 ring-slate-200'
          : 'text-slate-600 hover:text-slate-900'
      "
      @click="emit('update:strategy', 'APPEND_UNIQUE')"
    >
      <Layers class="h-3.5 w-3.5" aria-hidden="true" />
      <span>{{ t.merge.APPEND_UNIQUE_SHORT }}</span>
    </button>
  </div>
  <span
    v-else
    class="inline-flex items-center gap-1 rounded border px-2 py-0.5 text-xs font-medium"
    :class="
      props.strategy === 'OVERRIDE'
        ? 'border-blue-200 bg-blue-50 text-blue-800'
        : 'border-emerald-200 bg-emerald-50 text-emerald-800'
    "
    :title="props.strategy === 'OVERRIDE' ? t.merge.OVERRIDE : t.merge.APPEND_UNIQUE"
  >
    <ArrowDownToLine v-if="props.strategy === 'OVERRIDE'" class="h-3 w-3 shrink-0" aria-hidden="true" />
    <Layers v-else class="h-3 w-3 shrink-0" aria-hidden="true" />
    <span>
      {{
        props.short
          ? props.strategy === 'OVERRIDE'
            ? t.merge.OVERRIDE_SHORT
            : t.merge.APPEND_UNIQUE_SHORT
          : props.strategy === 'OVERRIDE'
            ? t.merge.OVERRIDE
            : t.merge.APPEND_UNIQUE
      }}
    </span>
  </span>
</template>
