<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { AlertCircle, RefreshCw, Server } from 'lucide-vue-next'
import {
  ALL_PLATFORMS,
  api,
  type DashboardSummary,
  type OsFamily,
  type SchemaCatalogResponse
} from '@/api'
import OsBadge from '@/components/common/OsBadge.vue'
import DashboardActivityGrid from '@/components/dashboard/DashboardActivityGrid.vue'
import { useI18n } from '@/i18n'

const router = useRouter()
const { t } = useI18n()

const summary = ref<DashboardSummary | null>(null)
const catalog = ref<SchemaCatalogResponse | null>(null)
const loading = ref(true)
const error = ref<string | null>(null)

async function loadDashboard() {
  loading.value = true
  error.value = null
  try {
    const [sumRes, catRes] = await Promise.all([
      api.dashboard.summary(),
      api.dashboard.catalog().catch(() => null)
    ])
    summary.value = sumRes
    catalog.value = catRes
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Failed to load dashboard'
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  void loadDashboard()
})

const kpis = computed(() => {
  const s = summary.value
  return [
    { label: t.value.dashboard.totalDevices, value: s?.totalDevices ?? 0, filter: '', accent: 'border-l-slate-700 text-slate-900' },
    { label: t.value.dashboard.compliant, value: s?.compliantDevices ?? 0, filter: 'COMPLIANT', accent: 'border-l-emerald-600 text-emerald-700' },
    { label: t.value.dashboard.degraded, value: s?.degradedDevices ?? 0, filter: 'DEGRADED', accent: 'border-l-amber-500 text-amber-700' },
    { label: t.value.dashboard.error, value: s?.errorDevices ?? 0, filter: 'ERROR', accent: 'border-l-rose-600 text-rose-700' },
    { label: t.value.dashboard.offline, value: s?.offlineDevices ?? 0, filter: 'OFFLINE', accent: 'border-l-slate-400 text-slate-600' }
  ]
})

function osShare(os: OsFamily): number {
  const total = summary.value?.totalDevices || 0
  if (!total) return 0
  const count = summary.value?.deviceByOs?.[os] ?? 0
  return Math.round((count / total) * 100)
}
</script>

<template>
  <div class="space-y-6">
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div>
        <h1 class="text-2xl font-bold tracking-tight text-slate-900">{{ t.dashboard.title }}</h1>
        <p class="mt-1 text-sm text-slate-600">{{ t.dashboard.subtitle }}</p>
      </div>
      <button type="button" class="apm-btn-secondary" :disabled="loading" @click="loadDashboard">
        <RefreshCw class="h-4 w-4" :class="{ 'animate-spin': loading }" aria-hidden="true" />
        <span>{{ t.app.refresh }}</span>
      </button>
    </div>

    <div
      v-if="error"
      role="alert"
      class="flex items-center justify-between rounded-lg border border-rose-200 bg-rose-50 p-4 text-sm text-rose-800"
    >
      <div class="flex items-center gap-2.5">
        <AlertCircle class="h-5 w-5 shrink-0 text-rose-600" aria-hidden="true" />
        <span>{{ error }}</span>
      </div>
      <button type="button" class="apm-btn-secondary text-xs" @click="loadDashboard">
        {{ t.app.refresh }}
      </button>
    </div>

    <div v-if="loading && !summary" class="grid grid-cols-2 gap-4 lg:grid-cols-5" role="status" aria-busy="true">
      <div v-for="i in 5" :key="i" class="h-24 animate-pulse rounded-lg border border-slate-200 bg-white" />
    </div>

    <template v-else-if="summary">
      <div class="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        <button
          v-for="kpi in kpis"
          :key="kpi.label"
          type="button"
          class="apm-card border-l-4 p-4 text-left transition-colors hover:bg-slate-50"
          :class="kpi.accent"
          @click="router.push(kpi.filter ? `/devices?status=${kpi.filter}` : '/devices')"
        >
          <div class="text-xs font-medium text-slate-500">{{ kpi.label }}</div>
          <div class="mt-1.5 text-2xl font-bold">{{ kpi.value }}</div>
        </button>
      </div>

      <div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <section class="apm-card p-5">
          <h2 class="text-sm font-semibold text-slate-900">{{ t.dashboard.osDistribution }}</h2>
          <div class="mt-4 space-y-3.5">
            <button
              v-for="os in ALL_PLATFORMS"
              :key="os"
              type="button"
              class="block w-full rounded-md p-2 text-left transition-colors hover:bg-slate-50"
              @click="router.push(`/devices?os=${os}`)"
            >
              <div class="flex items-center justify-between text-xs">
                <OsBadge :os="os" />
                <span class="font-semibold text-slate-700">
                  {{ summary.deviceByOs?.[os] ?? 0 }} ({{ osShare(os) }}%)
                </span>
              </div>
              <div class="mt-2 h-2 w-full overflow-hidden rounded-full bg-slate-100">
                <div
                  class="h-full rounded-full transition-all"
                  :class="os === 'WINDOWS' ? 'bg-sky-600' : os === 'LINUX' ? 'bg-amber-500' : 'bg-slate-700'"
                  :style="{ width: `${osShare(os)}%` }"
                />
              </div>
            </button>
          </div>
        </section>

        <section class="apm-card p-5">
          <div class="flex items-center justify-between">
            <h2 class="text-sm font-semibold text-slate-900">{{ t.dashboard.domainCard }}</h2>
            <Server class="h-4 w-4 text-slate-400" aria-hidden="true" />
          </div>
          <dl class="mt-4 grid grid-cols-2 gap-4 text-sm">
            <div class="rounded-md bg-slate-50 p-3">
              <dt class="text-xs text-slate-500">{{ t.dashboard.domainLabel }}</dt>
              <dd class="mt-1 truncate font-mono text-sm font-semibold text-slate-900">
                {{ summary.ldapDomain || '—' }}
              </dd>
              <dd class="mt-0.5 text-xs text-blue-700">
                {{ summary.ldapSchema === 'ad' ? t.dashboard.schemaAd : t.dashboard.schemaLdap }}
              </dd>
            </div>
            <div class="grid grid-cols-2 gap-2 rounded-md bg-slate-50 p-3">
              <div>
                <dt class="text-xs text-slate-500">{{ t.dashboard.activePolicies }}</dt>
                <dd class="mt-1 text-xl font-bold text-slate-900">{{ summary.activePolicies }}</dd>
              </div>
              <div>
                <dt class="text-xs text-slate-500">{{ t.dashboard.activeAssignments }}</dt>
                <dd class="mt-1 text-xl font-bold text-slate-900">{{ summary.activeAssignments }}</dd>
              </div>
            </div>
          </dl>

          <div v-if="catalog?.deliveryAdapters?.length" class="mt-4 border-t border-slate-100 pt-3">
            <div class="text-xs font-medium text-slate-500">{{ t.dashboard.deliveryTitle }}</div>
            <div class="mt-2 flex flex-wrap gap-2">
              <span
                v-for="adapter in catalog.deliveryAdapters"
                :key="adapter.id"
                class="inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-xs"
                :class="
                  adapter.status === 'ACTIVE'
                    ? 'border-emerald-200 bg-emerald-50 font-medium text-emerald-800'
                    : 'border-slate-200 bg-slate-50 text-slate-500'
                "
              >
                <span
                  class="h-1.5 w-1.5 rounded-full"
                  :class="adapter.status === 'ACTIVE' ? 'bg-emerald-600' : 'bg-slate-400'"
                />
                <span>{{ adapter.name || adapter.id }}</span>
              </span>
            </div>
          </div>
        </section>
      </div>

      <DashboardActivityGrid :events="summary.recentEvents" />
    </template>
  </div>
</template>
