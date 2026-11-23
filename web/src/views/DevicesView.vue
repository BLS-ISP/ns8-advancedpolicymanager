<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { RefreshCw, Search, Trash2 } from 'lucide-vue-next'
import {
  api,
  type ComplianceStatus,
  type Device,
  type DeviceGroup,
  type OsFamily
} from '@/api'
import OsBadge from '@/components/common/OsBadge.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'
import DeviceDetailModal from '@/components/devices/DeviceDetailModal.vue'
import DeviceGroupsPanel from '@/components/devices/DeviceGroupsPanel.vue'
import { useI18n } from '@/i18n'

const route = useRoute()
const { t, formatDateTime } = useI18n()

const activeTab = ref<'devices' | 'groups'>('devices')
const search = ref('')
const osFilter = ref<OsFamily | ''>((route.query.os as OsFamily) || '')
const statusFilter = ref<ComplianceStatus | ''>((route.query.status as ComplianceStatus) || '')
const groupFilter = ref<string>('')

const devices = ref<Device[]>([])
const groups = ref<DeviceGroup[]>([])
const selectedDevice = ref<Device | null>(null)
const loading = ref(true)
const error = ref<string | null>(null)

async function loadData() {
  loading.value = true
  error.value = null
  try {
    const [devRes, grpRes] = await Promise.all([
      api.devices.list({
        search: search.value || undefined,
        osFamily: osFilter.value || undefined,
        complianceStatus: statusFilter.value || undefined,
        deviceGroupId: groupFilter.value || undefined,
        pageSize: 50
      }),
      api.deviceGroups.list({ pageSize: 50 })
    ])
    devices.value = devRes.data
    groups.value = grpRes.data
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Failed to load devices'
  } finally {
    loading.value = false
  }
}

watch([osFilter, statusFilter, groupFilter], () => {
  void loadData()
})

onMounted(() => {
  void loadData()
})

async function openDeviceDetails(dev: Device) {
  try {
    selectedDevice.value = await api.devices.get(dev.id)
  } catch {
    selectedDevice.value = dev
  }
}

function handleDeviceUpdated(updated: Device) {
  selectedDevice.value = updated
  void loadData()
}

async function removeDevice(dev: Device) {
  if (!window.confirm(t.value.devices.confirmDeleteDevice)) return
  await api.devices.remove(dev.id)
  void loadData()
}

function filterByGroupFromTab(groupId: string) {
  groupFilter.value = groupId
  activeTab.value = 'devices'
}
</script>

<template>
  <div class="space-y-5">
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div>
        <h1 class="text-2xl font-bold tracking-tight text-slate-900">{{ t.devices.title }}</h1>
        <p class="mt-1 text-sm text-slate-600">{{ t.devices.subtitle }}</p>
      </div>
      <button type="button" class="apm-btn-secondary" :disabled="loading" @click="loadData">
        <RefreshCw class="h-4 w-4" :class="{ 'animate-spin': loading }" aria-hidden="true" />
        <span>{{ t.app.refresh }}</span>
      </button>
    </div>

    <!-- Tabs -->
    <div class="border-b border-slate-200" role="tablist">
      <div class="flex gap-6">
        <button
          type="button"
          role="tab"
          :aria-selected="activeTab === 'devices'"
          class="border-b-2 pb-2.5 text-sm font-semibold transition-colors"
          :class="
            activeTab === 'devices'
              ? 'border-blue-600 text-blue-600'
              : 'border-transparent text-slate-600 hover:text-slate-900'
          "
          @click="activeTab = 'devices'"
        >
          {{ t.devices.tabDevices }} ({{ devices.length }})
        </button>
        <button
          type="button"
          role="tab"
          :aria-selected="activeTab === 'groups'"
          class="border-b-2 pb-2.5 text-sm font-semibold transition-colors"
          :class="
            activeTab === 'groups'
              ? 'border-blue-600 text-blue-600'
              : 'border-transparent text-slate-600 hover:text-slate-900'
          "
          @click="activeTab = 'groups'"
        >
          {{ t.devices.tabGroups }} ({{ groups.length }})
        </button>
      </div>
    </div>

    <p v-if="error" role="alert" class="rounded-md border border-rose-200 bg-rose-50 p-3 text-sm text-rose-800">
      {{ error }}
    </p>

    <template v-if="activeTab === 'devices'">
      <!-- Filter Bar -->
      <div class="apm-card grid grid-cols-1 gap-3 p-4 sm:grid-cols-2 lg:grid-cols-4">
        <div class="relative">
          <Search class="pointer-events-none absolute left-3 top-2 h-4 w-4 text-slate-400" aria-hidden="true" />
          <input
            v-model="search"
            type="search"
            class="apm-input pl-9"
            :placeholder="t.app.search"
            :aria-label="t.app.search"
            @keydown.enter="loadData"
          />
        </div>
        <select v-model="osFilter" class="apm-input" aria-label="OS filter">
          <option value="">{{ t.app.allOs }}</option>
          <option value="WINDOWS">Windows</option>
          <option value="LINUX">Linux</option>
          <option value="MACOS">macOS</option>
        </select>
        <select v-model="statusFilter" class="apm-input" aria-label="Status filter">
          <option value="">{{ t.devices.filterStatus }}</option>
          <option value="COMPLIANT">{{ t.status.COMPLIANT }}</option>
          <option value="DEGRADED">{{ t.status.DEGRADED }}</option>
          <option value="ERROR">{{ t.status.ERROR }}</option>
          <option value="OFFLINE">{{ t.status.OFFLINE }}</option>
        </select>
        <select v-model="groupFilter" class="apm-input" aria-label="Group filter">
          <option value="">{{ t.devices.filterGroup }}</option>
          <option v-for="grp in groups" :key="grp.id" :value="grp.id">{{ grp.name }}</option>
        </select>
      </div>

      <!-- Devices Table -->
      <div class="apm-card overflow-x-auto">
        <div v-if="!loading && devices.length === 0" class="py-12 text-center text-sm text-slate-500">
          {{ t.devices.emptyDevices }}
        </div>
        <table v-else class="min-w-full divide-y divide-slate-200 text-left text-sm">
          <thead class="bg-slate-50 text-xs font-semibold uppercase tracking-wide text-slate-600">
            <tr>
              <th class="px-4 py-3">{{ t.devices.hostname }}</th>
              <th class="px-4 py-3">{{ t.devices.os }}</th>
              <th class="px-4 py-3">{{ t.devices.currentUser }}</th>
              <th class="px-4 py-3">{{ t.devices.groups }}</th>
              <th class="px-4 py-3">Status</th>
              <th class="px-4 py-3">{{ t.devices.lastSeen }}</th>
              <th class="px-4 py-3 text-right">{{ t.app.actions }}</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-100 bg-white">
            <tr v-for="dev in devices" :key="dev.id" class="hover:bg-slate-50/70">
              <td class="px-4 py-3">
                <div class="font-mono font-semibold text-slate-900">{{ dev.hostname }}</div>
                <div class="text-xs text-slate-500">Rev. {{ dev.appliedRevision }} · Agent v{{ dev.agentVersion }}</div>
              </td>
              <td class="px-4 py-3">
                <OsBadge :os="dev.osFamily" compact />
                <div class="mt-0.5 text-xs text-slate-500">{{ dev.osVersion }}</div>
              </td>
              <td class="px-4 py-3 font-mono text-xs text-slate-700">{{ dev.currentUser || '—' }}</td>
              <td class="px-4 py-3">
                <div class="flex flex-wrap gap-1">
                  <span
                    v-for="gn in dev.deviceGroupNames"
                    :key="gn"
                    class="rounded bg-slate-100 px-2 py-0.5 text-xs text-slate-700"
                  >
                    {{ gn }}
                  </span>
                  <span v-if="!dev.deviceGroupNames.length" class="text-xs text-slate-400">—</span>
                </div>
              </td>
              <td class="px-4 py-3"><StatusBadge :status="dev.complianceStatus" /></td>
              <td class="px-4 py-3 text-xs text-slate-600">{{ formatDateTime(dev.lastSeenAt) }}</td>
              <td class="px-4 py-3 text-right">
                <div class="inline-flex items-center gap-1.5">
                  <button type="button" class="apm-btn-secondary py-1 px-2.5 text-xs" @click="openDeviceDetails(dev)">
                    {{ t.devices.detailsBtn }}
                  </button>
                  <button
                    type="button"
                    class="rounded p-1.5 text-slate-400 hover:bg-rose-50 hover:text-rose-700"
                    :aria-label="t.app.delete"
                    @click="removeDevice(dev)"
                  >
                    <Trash2 class="h-4 w-4" />
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>

    <DeviceGroupsPanel
      v-else
      :groups="groups"
      @changed="loadData"
      @filter-group="filterByGroupFromTab"
    />

    <DeviceDetailModal
      :device="selectedDevice"
      :all-groups="groups"
      @close="selectedDevice = null"
      @updated="handleDeviceUpdated"
    />
  </div>
</template>
