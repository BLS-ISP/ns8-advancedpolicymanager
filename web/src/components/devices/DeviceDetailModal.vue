<script setup lang="ts">
import { ref, watch } from 'vue'
import { api, type Device, type DeviceGroup, type RuleType } from '@/api'
import ModalDialog from '@/components/common/ModalDialog.vue'
import OsBadge from '@/components/common/OsBadge.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'
import { useI18n } from '@/i18n'

const props = defineProps<{
  device: Device | null
  allGroups: DeviceGroup[]
}>()

const emit = defineEmits<{
  (e: 'close'): void
  (e: 'updated', device: Device): void
}>()

const { t, formatDateTime } = useI18n()
const selectedGroupIds = ref<string[]>([])
const saving = ref(false)
const error = ref<string | null>(null)

watch(
  () => props.device,
  (dev) => {
    selectedGroupIds.value = dev ? [...dev.deviceGroupIds] : []
    error.value = null
  },
  { immediate: true }
)

function toggleGroup(groupId: string) {
  if (selectedGroupIds.value.includes(groupId)) {
    selectedGroupIds.value = selectedGroupIds.value.filter((id) => id !== groupId)
  } else {
    selectedGroupIds.value = [...selectedGroupIds.value, groupId]
  }
}

async function saveDeviceGroups() {
  if (!props.device) return
  saving.value = true
  error.value = null
  try {
    const updated = await api.devices.update(props.device.id, {
      deviceGroupIds: selectedGroupIds.value
    })
    emit('updated', updated)
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Failed to update device groups'
  } finally {
    saving.value = false
  }
}

function ruleDisplayName(ruleType: string): string {
  return (t.value.ruleNames as Record<RuleType | string, string>)[ruleType] ?? ruleType
}
</script>

<template>
  <ModalDialog
    :open="Boolean(device)"
    :title="device ? `${t.devices.modalTitle}: ${device.hostname}` : t.devices.modalTitle"
    max-width-class="max-w-3xl"
    @close="emit('close')"
  >
    <div v-if="device" class="space-y-5">
      <div class="grid grid-cols-2 gap-3 rounded-lg border border-slate-200 bg-slate-50 p-3.5 text-xs sm:grid-cols-4">
        <div>
          <div class="text-slate-500">{{ t.devices.os }}</div>
          <div class="mt-1 flex items-center gap-1.5">
            <OsBadge :os="device.osFamily" compact />
          </div>
          <div class="mt-0.5 text-slate-600">{{ device.osVersion }} ({{ device.arch }})</div>
        </div>
        <div>
          <div class="text-slate-500">{{ t.devices.currentUser }}</div>
          <div class="mt-1 font-mono font-semibold text-slate-900">{{ device.currentUser || '—' }}</div>
          <div class="mt-0.5 text-slate-500">Agent v{{ device.agentVersion }}</div>
        </div>
        <div>
          <div class="text-slate-500">Compliance / Revision</div>
          <div class="mt-1"><StatusBadge :status="device.complianceStatus" /></div>
          <div class="mt-0.5 text-slate-600">Revision {{ device.appliedRevision }}</div>
        </div>
        <div>
          <div class="text-slate-500">{{ t.devices.lastSeen }}</div>
          <div class="mt-1 font-medium text-slate-900">{{ formatDateTime(device.lastSeenAt) }}</div>
        </div>
      </div>

      <!-- Device Group Assignment -->
      <div class="rounded-lg border border-slate-200 p-4">
        <div class="flex items-center justify-between gap-2">
          <h3 class="text-sm font-semibold text-slate-900">{{ t.devices.assignGroupsLabel }}</h3>
          <button
            type="button"
            class="apm-btn-primary py-1.5 text-xs"
            :disabled="saving"
            @click="saveDeviceGroups"
          >
            {{ saving ? t.app.saving : t.devices.saveGroups }}
          </button>
        </div>

        <p v-if="error" role="alert" class="mt-2 text-xs text-rose-700">{{ error }}</p>

        <div class="mt-3 flex flex-wrap gap-2">
          <label
            v-for="grp in allGroups"
            :key="grp.id"
            class="inline-flex cursor-pointer items-center gap-2 rounded-md border px-3 py-1.5 text-xs font-medium transition-colors"
            :class="
              selectedGroupIds.includes(grp.id)
                ? 'border-blue-600 bg-blue-50 text-blue-900'
                : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50'
            "
          >
            <input
              type="checkbox"
              class="h-3.5 w-3.5 rounded border-slate-300 text-blue-600"
              :checked="selectedGroupIds.includes(grp.id)"
              @change="toggleGroup(grp.id)"
            />
            <span>{{ grp.name }}</span>
          </label>
        </div>
      </div>

      <!-- Per-Rule Compliance & Rollback Table -->
      <div>
        <h3 class="text-sm font-semibold text-slate-900">{{ t.devices.complianceTable }}</h3>
        <p
          v-if="!device.complianceItems?.length"
          class="mt-2 rounded-md border border-slate-200 bg-slate-50 p-4 text-center text-xs text-slate-500"
        >
          {{ t.devices.noComplianceItems }}
        </p>
        <div v-else class="mt-2 overflow-x-auto rounded-lg border border-slate-200">
          <table class="min-w-full divide-y divide-slate-200 text-left text-xs">
            <thead class="bg-slate-50 font-semibold uppercase tracking-wide text-slate-600">
              <tr>
                <th class="px-3 py-2">Regel / Rule</th>
                <th class="px-3 py-2">Aktion</th>
                <th class="px-3 py-2">Status</th>
                <th class="px-3 py-2">Nachricht / Details</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-100 bg-white">
              <tr v-for="(item, idx) in device.complianceItems" :key="`${item.ruleType}-${idx}`">
                <td class="px-3 py-2.5">
                  <div class="font-medium text-slate-900">{{ ruleDisplayName(item.ruleType) }}</div>
                  <div class="font-mono text-[11px] text-slate-500">{{ item.ruleType }}</div>
                </td>
                <td class="px-3 py-2.5">
                  <StatusBadge v-if="item.action" :status="item.action" />
                  <span v-else class="text-slate-400">—</span>
                </td>
                <td class="px-3 py-2.5">
                  <StatusBadge :status="item.status" />
                </td>
                <td class="px-3 py-2.5 font-mono text-slate-700">{{ item.message }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <template #footer>
      <button type="button" class="apm-btn-secondary" @click="emit('close')">
        {{ t.app.close }}
      </button>
    </template>
  </ModalDialog>
</template>
