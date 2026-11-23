<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ArrowDown, ArrowUp, Edit2, Info, ListOrdered, Plus, Trash2 } from 'lucide-vue-next'
import {
  api,
  type Assignment,
  type AssignmentInput,
  type Device,
  type DeviceGroup,
  type Policy
} from '@/api'
import AssignmentFormModal from '@/components/assignments/AssignmentFormModal.vue'
import OsBadges from '@/components/common/OsBadges.vue'
import { useI18n } from '@/i18n'

const { t } = useI18n()

const assignments = ref<Assignment[]>([])
const policies = ref<Policy[]>([])
const deviceGroups = ref<DeviceGroup[]>([])
const devices = ref<Device[]>([])

const loading = ref(true)
const reordering = ref(false)
const saving = ref(false)
const error = ref<string | null>(null)
const modalError = ref<string | null>(null)
const modalOpen = ref(false)
const editingAssignment = ref<Assignment | null>(null)

async function loadAll() {
  loading.value = true
  error.value = null
  try {
    const [asgRes, polRes, grpRes, devRes] = await Promise.all([
      api.assignments.list({ pageSize: 100 }),
      api.policies.list({ pageSize: 100 }),
      api.deviceGroups.list({ pageSize: 100 }),
      api.devices.list({ pageSize: 100 })
    ])
    assignments.value = [...asgRes.data].sort((a, b) => a.priority - b.priority)
    policies.value = polRes.data
    deviceGroups.value = grpRes.data
    devices.value = devRes.data
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Failed to load assignments'
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  void loadAll()
})

function openCreate() {
  editingAssignment.value = null
  modalError.value = null
  modalOpen.value = true
}

function openEdit(asg: Assignment) {
  editingAssignment.value = asg
  modalError.value = null
  modalOpen.value = true
}

async function handleSave(payload: AssignmentInput) {
  saving.value = true
  modalError.value = null
  try {
    if (editingAssignment.value) {
      await api.assignments.update(editingAssignment.value.id, payload)
    } else {
      await api.assignments.create(payload)
    }
    modalOpen.value = false
    await loadAll()
  } catch (err) {
    modalError.value = err instanceof Error ? err.message : 'Failed to save assignment'
  } finally {
    saving.value = false
  }
}

async function movePriority(index: number, delta: -1 | 1) {
  const targetIndex = index + delta
  if (targetIndex < 0 || targetIndex >= assignments.value.length) return
  reordering.value = true
  const reordered = [...assignments.value]
  const [moved] = reordered.splice(index, 1)
  reordered.splice(targetIndex, 0, moved)
  assignments.value = reordered.map((item, i) => ({ ...item, priority: i + 1 }))
  try {
    await api.assignments.reorder({
      orderedAssignmentIds: assignments.value.map((a) => a.id)
    })
    await loadAll()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Reorder failed'
    await loadAll()
  } finally {
    reordering.value = false
  }
}

async function toggleEnabled(asg: Assignment) {
  await api.assignments.update(asg.id, { isEnabled: !asg.isEnabled })
  await loadAll()
}

async function deleteAssignment(asg: Assignment) {
  await api.assignments.remove(asg.id)
  await loadAll()
}

function formatWho(asg: Assignment): string {
  if (asg.targetUserType === 'ALL') return t.value.assignments.whoAll
  if (asg.targetUserType === 'GROUP') return `${t.value.assignments.whoGroup}: ${asg.targetUserRef}`
  return `${t.value.assignments.whoUser}: ${asg.targetUserRef}`
}

function formatWhere(asg: Assignment): string {
  if (asg.targetDeviceType === 'ALL') return t.value.assignments.whereAll
  if (asg.targetDeviceType === 'DEVICE_GROUP') {
    const label =
      asg.targetDeviceGroupName ||
      deviceGroups.value.find((g) => g.id === asg.targetDeviceRef)?.name ||
      asg.targetDeviceRef
    return `${t.value.assignments.whereGroup}: ${label}`
  }
  const hostname =
    devices.value.find((d) => d.id === asg.targetDeviceRef)?.hostname || asg.targetDeviceRef
  return `${t.value.assignments.whereDevice}: ${hostname}`
}
</script>

<template>
  <div class="space-y-5">
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div>
        <h1 class="text-2xl font-bold tracking-tight text-slate-900">{{ t.assignments.title }}</h1>
        <p class="mt-1 text-sm text-slate-600">{{ t.assignments.subtitle }}</p>
      </div>
      <button type="button" class="apm-btn-primary" :disabled="!policies.length" @click="openCreate">
        <Plus class="h-4 w-4" aria-hidden="true" />
        <span>{{ t.assignments.newAssignment }}</span>
      </button>
    </div>

    <div class="flex items-start gap-2.5 rounded-lg border border-blue-200 bg-blue-50/70 p-3.5 text-xs text-slate-700">
      <Info class="mt-0.5 h-4 w-4 shrink-0 text-blue-600" aria-hidden="true" />
      <span>{{ t.assignments.priorityHelp }}</span>
    </div>

    <p v-if="error" role="alert" class="rounded-md border border-rose-200 bg-rose-50 p-3 text-sm text-rose-800">
      {{ error }}
    </p>

    <div v-if="!loading && assignments.length === 0" class="apm-card py-14 text-center">
      <ListOrdered class="mx-auto h-10 w-10 text-slate-400" aria-hidden="true" />
      <h2 class="mt-3 text-sm font-semibold text-slate-900">{{ t.assignments.emptyTitle }}</h2>
      <p class="mt-1 text-xs text-slate-500">{{ t.assignments.emptyText }}</p>
    </div>

    <div v-else class="apm-card overflow-x-auto">
      <table class="min-w-full divide-y divide-slate-200 text-left text-sm">
        <thead class="bg-slate-50 text-xs font-semibold uppercase tracking-wide text-slate-600">
          <tr>
            <th class="px-4 py-3">{{ t.assignments.colPriority }}</th>
            <th class="px-4 py-3">{{ t.assignments.colPolicy }}</th>
            <th class="px-4 py-3">{{ t.assignments.colWho }}</th>
            <th class="px-4 py-3">{{ t.assignments.colWhere }}</th>
            <th class="px-4 py-3">{{ t.assignments.colOs }}</th>
            <th class="px-4 py-3">{{ t.assignments.colStatus }}</th>
            <th class="px-4 py-3 text-right">{{ t.app.actions }}</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-100 bg-white">
          <tr v-for="(asg, idx) in assignments" :key="asg.id" class="hover:bg-slate-50/70">
            <td class="px-4 py-3">
              <div class="inline-flex items-center gap-1.5">
                <span
                  class="inline-flex h-6 min-w-8 items-center justify-center rounded font-mono text-xs font-bold"
                  :class="idx === 0 ? 'bg-blue-600 text-white' : 'bg-slate-100 text-slate-800'"
                >
                  #{{ asg.priority }}
                </span>
                <div class="flex flex-col">
                  <button
                    type="button"
                    class="rounded p-0.5 text-slate-500 hover:bg-slate-200 disabled:opacity-30"
                    :disabled="idx === 0 || reordering"
                    :aria-label="t.assignments.moveUp"
                    @click="movePriority(idx, -1)"
                  >
                    <ArrowUp class="h-3.5 w-3.5" />
                  </button>
                  <button
                    type="button"
                    class="rounded p-0.5 text-slate-500 hover:bg-slate-200 disabled:opacity-30"
                    :disabled="idx === assignments.length - 1 || reordering"
                    :aria-label="t.assignments.moveDown"
                    @click="movePriority(idx, 1)"
                  >
                    <ArrowDown class="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            </td>
            <td class="px-4 py-3 font-semibold text-slate-900">{{ asg.policyName }}</td>
            <td class="px-4 py-3 text-xs text-slate-700">{{ formatWho(asg) }}</td>
            <td class="px-4 py-3 text-xs text-slate-700">{{ formatWhere(asg) }}</td>
            <td class="px-4 py-3"><OsBadges :platforms="asg.osFilter" compact /></td>
            <td class="px-4 py-3">
              <button
                type="button"
                class="rounded-full border px-2.5 py-0.5 text-xs font-medium"
                :class="
                  asg.isEnabled
                    ? 'border-emerald-200 bg-emerald-50 text-emerald-800'
                    : 'border-slate-200 bg-slate-100 text-slate-600'
                "
                @click="toggleEnabled(asg)"
              >
                {{ asg.isEnabled ? t.app.enabled : t.app.disabled }}
              </button>
            </td>
            <td class="px-4 py-3 text-right">
              <div class="inline-flex items-center gap-1">
                <button
                  type="button"
                  class="rounded p-1.5 text-slate-500 hover:bg-slate-100 hover:text-slate-900"
                  :aria-label="t.app.edit"
                  @click="openEdit(asg)"
                >
                  <Edit2 class="h-4 w-4" />
                </button>
                <button
                  type="button"
                  class="rounded p-1.5 text-slate-400 hover:bg-rose-50 hover:text-rose-700"
                  :aria-label="t.app.delete"
                  @click="deleteAssignment(asg)"
                >
                  <Trash2 class="h-4 w-4" />
                </button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <AssignmentFormModal
      :open="modalOpen"
      :editing="editingAssignment"
      :next-priority="assignments.length + 1"
      :policies="policies"
      :device-groups="deviceGroups"
      :devices="devices"
      :saving="saving"
      :error="modalError"
      @close="modalOpen = false"
      @save="handleSave"
    />
  </div>
</template>
