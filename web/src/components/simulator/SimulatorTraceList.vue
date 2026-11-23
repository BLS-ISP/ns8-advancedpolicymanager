<script setup lang="ts">
import { Award } from 'lucide-vue-next'
import type { RuleResolutionTrace, RuleType } from '@/api'
import MergeStrategyBadge from '@/components/common/MergeStrategyBadge.vue'
import { useI18n } from '@/i18n'

defineProps<{
  traces: RuleResolutionTrace[]
}>()

const { t } = useI18n()

function ruleLabel(rt: RuleType | string): string {
  return (t.value.ruleNames as Record<string, string>)[rt] ?? rt
}
</script>

<template>
  <div class="space-y-3">
    <article
      v-for="tr in traces"
      :key="tr.ruleType"
      class="rounded-lg border border-slate-200 bg-white p-4"
    >
      <div class="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div class="text-sm font-semibold text-slate-900">{{ ruleLabel(tr.ruleType) }}</div>
          <div class="font-mono text-[11px] text-slate-500">{{ tr.ruleType }}</div>
        </div>
        <MergeStrategyBadge :strategy="tr.mergeStrategy" short />
      </div>

      <!-- Winning Policy -->
      <div class="mt-3 flex items-center justify-between rounded-md border border-emerald-200 bg-emerald-50/70 px-3 py-2 text-xs">
        <div class="flex items-center gap-2">
          <Award class="h-4 w-4 text-emerald-700" aria-hidden="true" />
          <span class="font-medium text-emerald-900">{{ t.simulator.winnerLabel }}:</span>
          <strong class="font-semibold text-slate-900">{{ tr.winningPolicyName }}</strong>
        </div>
        <span class="rounded bg-emerald-700 px-1.5 py-0.5 font-mono text-[11px] font-bold text-white">
          #{{ tr.winningPriority }}
        </span>
      </div>

      <!-- Shadowed / Merged Policies -->
      <ul v-if="tr.shadowedPolicies.length" class="mt-2 space-y-1.5 pl-3">
        <li
          v-for="sh in tr.shadowedPolicies"
          :key="`${sh.policyId}-${sh.priority}`"
          class="flex items-center justify-between rounded border border-slate-200 bg-slate-50 px-2.5 py-1.5 text-xs"
        >
          <div class="flex items-center gap-2">
            <span class="font-mono text-slate-500">#{{ sh.priority }}</span>
            <span class="font-medium text-slate-700">{{ sh.policyName }}</span>
          </div>
          <span
            class="rounded px-2 py-0.5 text-[11px] font-semibold"
            :class="
              sh.action === 'MERGED'
                ? 'bg-blue-100 text-blue-800'
                : 'bg-amber-100 text-amber-900'
            "
          >
            {{ sh.action === 'MERGED' ? t.simulator.mergedLabel : t.simulator.overriddenLabel }}
          </span>
        </li>
      </ul>
    </article>
  </div>
</template>
