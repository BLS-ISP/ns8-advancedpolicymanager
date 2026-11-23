<script setup lang="ts">
import { computed } from 'vue'
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  MinusCircle,
  RotateCcw,
  ShieldCheck,
  WifiOff,
  XCircle
} from 'lucide-vue-next'
import { useI18n } from '@/i18n'

type KnownStatus =
  | 'COMPLIANT'
  | 'DEGRADED'
  | 'ERROR'
  | 'OFFLINE'
  | 'PENDING'
  | 'APPLIED'
  | 'SKIPPED_UNSUPPORTED'
  | 'FAILED'
  | 'ENFORCED'
  | 'ROLLED_BACK'

const props = defineProps<{
  status: KnownStatus | string
}>()

const { t } = useI18n()

const meta = computed(() => {
  const key = props.status as KnownStatus
  const label = (t.value.status as Record<string, string>)[key] ?? props.status

  switch (key) {
    case 'COMPLIANT':
    case 'APPLIED':
      return {
        label,
        icon: CheckCircle2,
        classes: 'bg-emerald-50 text-emerald-800 border-emerald-200'
      }
    case 'ENFORCED':
      return {
        label,
        icon: ShieldCheck,
        classes: 'bg-blue-50 text-blue-800 border-blue-200'
      }
    case 'ROLLED_BACK':
      return {
        label,
        icon: RotateCcw,
        classes: 'bg-slate-100 text-slate-700 border-slate-300'
      }
    case 'DEGRADED':
    case 'SKIPPED_UNSUPPORTED':
      return {
        label,
        icon: AlertTriangle,
        classes: 'bg-amber-50 text-amber-800 border-amber-200'
      }
    case 'ERROR':
    case 'FAILED':
      return {
        label,
        icon: XCircle,
        classes: 'bg-rose-50 text-rose-800 border-rose-200'
      }
    case 'OFFLINE':
      return {
        label,
        icon: WifiOff,
        classes: 'bg-slate-100 text-slate-700 border-slate-300'
      }
    case 'PENDING':
      return {
        label,
        icon: Clock,
        classes: 'bg-slate-100 text-slate-700 border-slate-200'
      }
    default:
      return {
        label,
        icon: MinusCircle,
        classes: 'bg-slate-100 text-slate-700 border-slate-200'
      }
  }
})
</script>

<template>
  <span
    class="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 py-0.5 text-xs font-medium"
    :class="meta.classes"
  >
    <component :is="meta.icon" class="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
    <span>{{ meta.label }}</span>
  </span>
</template>
