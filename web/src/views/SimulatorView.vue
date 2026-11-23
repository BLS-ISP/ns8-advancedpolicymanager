<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { Play, Users } from 'lucide-vue-next'
import {
  api,
  type Device,
  type DeviceGroup,
  type OsFamily,
  type SimulatorEvaluateResponse
} from '@/api'
import DirectoryPicker from '@/components/common/DirectoryPicker.vue'
import OsBadge from '@/components/common/OsBadge.vue'
import EffectiveRuleCard from '@/components/simulator/EffectiveRuleCard.vue'
import SimulatorTraceList from '@/components/simulator/SimulatorTraceList.vue'
import { useI18n } from '@/i18n'

const { t } = useI18n()

const devices = ref<Device[]>([])
const deviceGroups = ref<DeviceGroup[]>([])

const username = ref('m.mueller')
const targetMode = ref<'device' | 'virtual'>('device')
const selectedDeviceId = ref('')
const osOverride = ref<OsFamily>('WINDOWS')
const virtualGroupIds = ref<string[]>([])

const running = ref(false)
const error = ref<string | null>(null)
const result = ref<SimulatorEvaluateResponse | null>(null)

onMounted(async () => {
  try {
    const [devRes, grpRes, usrRes] = await Promise.all([
      api.devices.list({ pageSize: 100 }),
      api.deviceGroups.list({ pageSize: 100 }),
      api.directory.listUsers({ pageSize: 5 })
    ])
    devices.value = devRes.data
    deviceGroups.value = grpRes.data
    if (devRes.data.length > 0) {
      selectedDeviceId.value = devRes.data[0].id
    } else {
      targetMode.value = 'virtual'
    }
    if (usrRes.data.length > 0 && !username.value) {
      username.value = usrRes.data[0].username
    }
  } catch {
    targetMode.value = 'virtual'
  }
})

function toggleVirtualGroup(id: string) {
  if (virtualGroupIds.value.includes(id)) {
    virtualGroupIds.value = virtualGroupIds.value.filter((g) => g !== id)
  } else {
    virtualGroupIds.value = [...virtualGroupIds.value, id]
  }
}

async function runSimulation() {
  if (!username.value.trim()) return
  running.value = true
  error.value = null
  try {
    result.value = await api.simulator.evaluate({
      username: username.value.trim(),
      deviceId: targetMode.value === 'device' ? selectedDeviceId.value || null : null,
      osFamilyOverride: targetMode.value === 'virtual' ? osOverride.value : null,
      deviceGroupIds: targetMode.value === 'virtual' ? virtualGroupIds.value : undefined
    })
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Simulation failed'
  } finally {
    running.value = false
  }
}
</script>

<template>
  <div class="space-y-6">
    <div>
      <h1 class="text-2xl font-bold tracking-tight text-slate-900">{{ t.simulator.title }}</h1>
      <p class="mt-1 text-sm text-slate-600">{{ t.simulator.subtitle }}</p>
    </div>

    <!-- Input Panel -->
    <form class="apm-card space-y-4 p-5" @submit.prevent="runSimulation">
      <div class="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <DirectoryPicker
          v-model="username"
          kind="USER"
          input-id="sim-user"
          :label="t.simulator.selectUser"
          :placeholder="t.simulator.userPlaceholder"
        />

        <div>
          <span class="apm-label">{{ t.simulator.targetModeLabel }}</span>
          <div class="grid grid-cols-2 gap-1 rounded-md border border-slate-200 bg-slate-50 p-1">
            <button
              type="button"
              class="rounded py-1 text-xs font-semibold"
              :class="targetMode === 'device' ? 'bg-white text-blue-700 shadow-sm' : 'text-slate-600'"
              @click="targetMode = 'device'"
            >
              {{ t.simulator.targetModeDevice }}
            </button>
            <button
              type="button"
              class="rounded py-1 text-xs font-semibold"
              :class="targetMode === 'virtual' ? 'bg-white text-blue-700 shadow-sm' : 'text-slate-600'"
              @click="targetMode = 'virtual'"
            >
              {{ t.simulator.targetModeVirtual }}
            </button>
          </div>
        </div>

        <div v-if="targetMode === 'device'">
          <label for="sim-dev" class="apm-label">{{ t.simulator.selectDevice }}</label>
          <select id="sim-dev" v-model="selectedDeviceId" class="apm-input">
            <option v-for="dev in devices" :key="dev.id" :value="dev.id">
              {{ dev.hostname }} ({{ dev.osFamily }})
            </option>
          </select>
        </div>

        <div v-else>
          <label for="sim-os" class="apm-label">{{ t.simulator.selectOs }}</label>
          <select id="sim-os" v-model="osOverride" class="apm-input">
            <option value="WINDOWS">Windows</option>
            <option value="LINUX">Linux</option>
            <option value="MACOS">macOS</option>
          </select>
        </div>
      </div>

      <div v-if="targetMode === 'virtual' && deviceGroups.length > 0">
        <span class="apm-label">{{ t.simulator.selectGroups }}</span>
        <div class="flex flex-wrap gap-2">
          <label
            v-for="grp in deviceGroups"
            :key="grp.id"
            class="inline-flex cursor-pointer items-center gap-1.5 rounded border px-2.5 py-1 text-xs"
            :class="
              virtualGroupIds.includes(grp.id)
                ? 'border-blue-600 bg-blue-50 text-blue-900'
                : 'border-slate-200 text-slate-700'
            "
          >
            <input
              type="checkbox"
              class="h-3.5 w-3.5 rounded border-slate-300 text-blue-600"
              :checked="virtualGroupIds.includes(grp.id)"
              @change="toggleVirtualGroup(grp.id)"
            />
            <span>{{ grp.name }}</span>
          </label>
        </div>
      </div>

      <div class="flex justify-end border-t border-slate-100 pt-3">
        <button
          type="submit"
          class="apm-btn-primary"
          :disabled="running || !username.trim() || (targetMode === 'device' && !selectedDeviceId)"
        >
          <Play class="h-4 w-4" aria-hidden="true" />
          <span>{{ running ? t.simulator.running : t.simulator.runBtn }}</span>
        </button>
      </div>
    </form>

    <p v-if="error" role="alert" class="rounded-md border border-rose-200 bg-rose-50 p-3 text-sm text-rose-800">
      {{ error }}
    </p>

    <!-- Results -->
    <template v-if="result">
      <div class="apm-card flex flex-wrap items-center justify-between gap-4 bg-slate-50/70 p-4 text-xs">
        <div class="flex flex-wrap items-center gap-2">
          <Users class="h-4 w-4 text-blue-600" aria-hidden="true" />
          <span class="font-semibold text-slate-800">{{ result.username }}</span>
          <span class="text-slate-500">→ {{ t.simulator.resolvedGroups }}:</span>
          <span
            v-for="grp in result.resolvedUserGroups"
            :key="grp"
            class="rounded border border-blue-200 bg-blue-50 px-2 py-0.5 font-medium text-blue-900"
          >
            {{ grp }}
          </span>
        </div>

        <div class="flex items-center gap-2">
          <span class="font-mono font-semibold text-slate-900">{{ result.device.hostname }}</span>
          <OsBadge :os="result.device.osFamily" compact />
        </div>
      </div>

      <div
        v-if="!result.effectiveRules.length"
        class="apm-card py-12 text-center text-sm text-slate-500"
      >
        {{ t.simulator.noEffectiveRules }}
      </div>

      <div v-else class="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <section class="space-y-3">
          <h2 class="text-base font-semibold text-slate-900">
            {{ t.simulator.effectiveHeading }} ({{ result.effectiveRules.length }})
          </h2>
          <EffectiveRuleCard v-for="rule in result.effectiveRules" :key="rule.ruleId" :rule="rule" />
        </section>

        <section class="space-y-3">
          <h2 class="text-base font-semibold text-slate-900">
            {{ t.simulator.traceHeading }} ({{ result.trace.length }})
          </h2>
          <SimulatorTraceList :traces="result.trace" />
        </section>
      </div>
    </template>
  </div>
</template>
