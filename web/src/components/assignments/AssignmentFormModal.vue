<script setup lang="ts">
import { ref, watch } from 'vue'
import {
  ALL_PLATFORMS,
  type Assignment,
  type AssignmentInput,
  type Device,
  type DeviceGroup,
  type OsFamily,
  type Policy,
  type TargetDeviceType,
  type TargetUserType
} from '@/api'
import DirectoryPicker from '@/components/common/DirectoryPicker.vue'
import ModalDialog from '@/components/common/ModalDialog.vue'
import OsBadges from '@/components/common/OsBadges.vue'
import { useI18n } from '@/i18n'

const props = defineProps<{
  open: boolean
  editing: Assignment | null
  nextPriority: number
  policies: Policy[]
  deviceGroups: DeviceGroup[]
  devices: Device[]
  saving: boolean
  error: string | null
}>()

const emit = defineEmits<{
  (e: 'close'): void
  (e: 'save', payload: AssignmentInput): void
}>()

const { t } = useI18n()

const policyId = ref('')
const priority = ref(1)
const isEnabled = ref(true)
const targetUserType = ref<TargetUserType>('ALL')
const targetUserRef = ref('')
const targetDeviceType = ref<TargetDeviceType>('ALL')
const targetDeviceRef = ref('')
const osFilter = ref<OsFamily[]>([...ALL_PLATFORMS])

watch(
  () => [props.open, props.editing] as const,
  ([isOpen, item]) => {
    if (!isOpen) return
    if (item) {
      policyId.value = item.policyId
      priority.value = item.priority
      isEnabled.value = item.isEnabled
      targetUserType.value = item.targetUserType
      targetUserRef.value = item.targetUserRef || ''
      targetDeviceType.value = item.targetDeviceType
      targetDeviceRef.value = item.targetDeviceRef || ''
      osFilter.value = item.osFilter.length ? [...item.osFilter] : [...ALL_PLATFORMS]
    } else {
      policyId.value = props.policies[0]?.id || ''
      priority.value = props.nextPriority
      isEnabled.value = true
      targetUserType.value = 'ALL'
      targetUserRef.value = ''
      targetDeviceType.value = 'ALL'
      targetDeviceRef.value = ''
      osFilter.value = [...ALL_PLATFORMS]
    }
  },
  { immediate: true }
)

function submitForm() {
  if (!policyId.value) return
  if (targetUserType.value !== 'ALL' && !targetUserRef.value.trim()) return
  if (targetDeviceType.value !== 'ALL' && !targetDeviceRef.value.trim()) return

  emit('save', {
    policyId: policyId.value,
    priority: Number(priority.value) || 1,
    isEnabled: isEnabled.value,
    targetUserType: targetUserType.value,
    targetUserRef: targetUserType.value === 'ALL' ? null : targetUserRef.value.trim(),
    targetDeviceType: targetDeviceType.value,
    targetDeviceRef: targetDeviceType.value === 'ALL' ? null : targetDeviceRef.value.trim(),
    osFilter: osFilter.value
  })
}
</script>

<template>
  <ModalDialog
    :open="open"
    :title="editing ? t.assignments.editAssignment : t.assignments.newAssignment"
    max-width-class="max-w-xl"
    @close="emit('close')"
  >
    <form id="assignment-form" class="space-y-4" @submit.prevent="submitForm">
      <p v-if="error" role="alert" class="rounded bg-rose-50 p-2.5 text-xs text-rose-700">
        {{ error }}
      </p>

      <div class="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div class="sm:col-span-2">
          <label for="asg-policy" class="apm-label">{{ t.assignments.colPolicy }}</label>
          <select id="asg-policy" v-model="policyId" required class="apm-input">
            <option v-for="pol in policies" :key="pol.id" :value="pol.id">{{ pol.name }}</option>
          </select>
        </div>

        <div>
          <label for="asg-prio" class="apm-label">{{ t.assignments.colPriority }}</label>
          <input id="asg-prio" v-model.number="priority" type="number" min="1" required class="apm-input" />
        </div>
      </div>

      <!-- WHO? -->
      <div class="rounded-md border border-slate-200 bg-slate-50/70 p-3.5 space-y-3">
        <div>
          <label for="asg-who-type" class="apm-label">{{ t.assignments.colWho }}</label>
          <select
            id="asg-who-type"
            v-model="targetUserType"
            class="apm-input"
            @change="targetUserRef = ''"
          >
            <option value="ALL">{{ t.assignments.whoAll }}</option>
            <option value="GROUP">{{ t.assignments.whoGroup }}</option>
            <option value="USER">{{ t.assignments.whoUser }}</option>
          </select>
        </div>

        <DirectoryPicker
          v-if="targetUserType === 'GROUP'"
          v-model="targetUserRef"
          kind="GROUP"
          input-id="asg-who-group"
          placeholder="Buchhaltung, IT-Admins…"
        />
        <DirectoryPicker
          v-else-if="targetUserType === 'USER'"
          v-model="targetUserRef"
          kind="USER"
          input-id="asg-who-user"
          placeholder="m.mueller…"
        />
      </div>

      <!-- WHERE? -->
      <div class="rounded-md border border-slate-200 bg-slate-50/70 p-3.5 space-y-3">
        <div>
          <label for="asg-where-type" class="apm-label">{{ t.assignments.colWhere }}</label>
          <select
            id="asg-where-type"
            v-model="targetDeviceType"
            class="apm-input"
            @change="targetDeviceRef = ''"
          >
            <option value="ALL">{{ t.assignments.whereAll }}</option>
            <option value="DEVICE_GROUP">{{ t.assignments.whereGroup }}</option>
            <option value="DEVICE">{{ t.assignments.whereDevice }}</option>
          </select>
        </div>

        <select
          v-if="targetDeviceType === 'DEVICE_GROUP'"
          v-model="targetDeviceRef"
          required
          class="apm-input"
          aria-label="Device group"
        >
          <option value="" disabled>—</option>
          <option v-for="grp in deviceGroups" :key="grp.id" :value="grp.id">{{ grp.name }}</option>
        </select>

        <select
          v-else-if="targetDeviceType === 'DEVICE'"
          v-model="targetDeviceRef"
          required
          class="apm-input"
          aria-label="Specific computer"
        >
          <option value="" disabled>—</option>
          <option v-for="dev in devices" :key="dev.id" :value="dev.id">
            {{ dev.hostname }} ({{ dev.osFamily }})
          </option>
        </select>
      </div>

      <!-- OS Filter & Active -->
      <div class="flex flex-wrap items-center justify-between gap-4 pt-1">
        <div>
          <span class="apm-label">{{ t.assignments.colOs }}</span>
          <OsBadges v-model:platforms="osFilter" editable />
        </div>

        <label class="inline-flex cursor-pointer items-center gap-2 text-sm font-medium text-slate-800">
          <input v-model="isEnabled" type="checkbox" class="h-4 w-4 rounded border-slate-300 text-blue-600" />
          <span>{{ isEnabled ? t.app.enabled : t.app.disabled }}</span>
        </label>
      </div>
    </form>

    <template #footer>
      <button type="button" class="apm-btn-secondary" @click="emit('close')">{{ t.app.cancel }}</button>
      <button type="submit" form="assignment-form" class="apm-btn-primary" :disabled="saving || !policyId">
        {{ saving ? t.app.saving : t.app.save }}
      </button>
    </template>
  </ModalDialog>
</template>
