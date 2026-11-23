<script setup lang="ts">
import { useRouter } from 'vue-router'
import { ArrowRight, FileSliders, FlaskConical, TerminalSquare } from 'lucide-vue-next'
import type { DashboardEvent } from '@/api'
import StatusBadge from '@/components/common/StatusBadge.vue'
import { useI18n } from '@/i18n'

defineProps<{
  events: DashboardEvent[]
}>()

const router = useRouter()
const { t, formatDateTime } = useI18n()
</script>

<template>
  <div class="grid grid-cols-1 gap-6 lg:grid-cols-3">
    <section class="apm-card p-5 lg:col-span-2">
      <h2 class="text-sm font-semibold text-slate-900">{{ t.dashboard.recentFeed }}</h2>
      <p v-if="!events.length" class="mt-6 py-6 text-center text-sm text-slate-500">
        {{ t.dashboard.noEvents }}
      </p>
      <ul v-else class="mt-3 divide-y divide-slate-100" role="list">
        <li
          v-for="evt in events"
          :key="evt.id"
          class="flex items-center justify-between gap-4 py-2.5 text-sm"
        >
          <div class="flex min-w-0 items-center gap-3">
            <StatusBadge :status="evt.status" />
            <div class="min-w-0 truncate">
              <span class="font-mono font-semibold text-slate-900">{{ evt.deviceHostname }}</span>
              <span class="ml-2 text-slate-600">{{ evt.message }}</span>
            </div>
          </div>
          <span class="shrink-0 whitespace-nowrap text-xs text-slate-500">{{ formatDateTime(evt.timestamp) }}</span>
        </li>
      </ul>
    </section>

    <section class="apm-card p-5">
      <h2 class="text-sm font-semibold text-slate-900">{{ t.dashboard.quickActions }}</h2>
      <div class="mt-3 space-y-2.5">
        <button
          type="button"
          class="flex w-full items-center justify-between rounded-md border border-slate-200 p-3 text-left text-sm font-medium text-slate-800 transition-colors hover:border-blue-300 hover:bg-blue-50/50"
          @click="router.push('/policies?new=1')"
        >
          <span class="flex items-center gap-2.5">
            <FileSliders class="h-4 w-4 text-blue-600" aria-hidden="true" />
            <span>{{ t.dashboard.qaNewPolicy }}</span>
          </span>
          <ArrowRight class="h-4 w-4 text-slate-400" aria-hidden="true" />
        </button>

        <button
          type="button"
          class="flex w-full items-center justify-between rounded-md border border-slate-200 p-3 text-left text-sm font-medium text-slate-800 transition-colors hover:border-blue-300 hover:bg-blue-50/50"
          @click="router.push('/simulator')"
        >
          <span class="flex items-center gap-2.5">
            <FlaskConical class="h-4 w-4 text-blue-600" aria-hidden="true" />
            <span>{{ t.dashboard.qaSimulate }}</span>
          </span>
          <ArrowRight class="h-4 w-4 text-slate-400" aria-hidden="true" />
        </button>

        <button
          type="button"
          class="flex w-full items-center justify-between rounded-md border border-slate-200 p-3 text-left text-sm font-medium text-slate-800 transition-colors hover:border-blue-300 hover:bg-blue-50/50"
          @click="router.push('/enroll')"
        >
          <span class="flex items-center gap-2.5">
            <TerminalSquare class="h-4 w-4 text-blue-600" aria-hidden="true" />
            <span>{{ t.dashboard.qaEnroll }}</span>
          </span>
          <ArrowRight class="h-4 w-4 text-slate-400" aria-hidden="true" />
        </button>
      </div>
    </section>
  </div>
</template>
