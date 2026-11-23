<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { Check, Copy, KeyRound, Plus, Trash2 } from 'lucide-vue-next'
import { api, type DeviceGroup, type EnrollmentToken } from '@/api'
import RolloutCommandsCard from '@/components/enroll/RolloutCommandsCard.vue'
import { useI18n } from '@/i18n'

const { t, formatDateTime } = useI18n()

const tokens = ref<EnrollmentToken[]>([])
const deviceGroups = ref<DeviceGroup[]>([])
const createdToken = ref<EnrollmentToken | null>(null)
const loading = ref(true)
const creating = ref(false)
const error = ref<string | null>(null)
const copiedPlain = ref(false)

const formName = ref('Standard-Rollout')
const formGroupId = ref<string>('')
const formExpiresHours = ref<number>(168)
const formMaxUses = ref<number>(50)

async function loadData() {
  loading.value = true
  error.value = null
  try {
    const [tokRes, grpRes] = await Promise.all([
      api.enrollmentTokens.list({ pageSize: 50 }),
      api.deviceGroups.list({ pageSize: 50 })
    ])
    tokens.value = tokRes.data
    deviceGroups.value = grpRes.data
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Failed to load enrollment tokens'
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  void loadData()
})

async function handleCreateToken() {
  if (!formName.value.trim()) return
  creating.value = true
  error.value = null
  try {
    const created = await api.enrollmentTokens.create({
      name: formName.value.trim(),
      defaultDeviceGroupId: formGroupId.value || null,
      expiresInHours: Number(formExpiresHours.value) || 168,
      maxUses: Number(formMaxUses.value) || 50
    })
    createdToken.value = created
    await loadData()
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Failed to create token'
  } finally {
    creating.value = false
  }
}

async function copyPlainToken() {
  if (!createdToken.value?.plainToken) return
  await navigator.clipboard.writeText(createdToken.value.plainToken)
  copiedPlain.value = true
  setTimeout(() => {
    copiedPlain.value = false
  }, 2000)
}

async function revokeToken(tok: EnrollmentToken) {
  if (!window.confirm(t.value.enroll.confirmRevoke)) return
  await api.enrollmentTokens.remove(tok.id)
  if (createdToken.value?.id === tok.id) {
    createdToken.value = null
  }
  await loadData()
}
</script>

<template>
  <div class="space-y-6">
    <div>
      <h1 class="text-2xl font-bold tracking-tight text-slate-900">{{ t.enroll.title }}</h1>
      <p class="mt-1 text-sm text-slate-600">{{ t.enroll.subtitle }}</p>
    </div>

    <p v-if="error" role="alert" class="rounded-md border border-rose-200 bg-rose-50 p-3 text-sm text-rose-800">
      {{ error }}
    </p>

    <!-- Create Token Card -->
    <section class="apm-card p-5">
      <h2 class="text-base font-semibold text-slate-900">{{ t.enroll.createCardTitle }}</h2>
      <form class="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4" @submit.prevent="handleCreateToken">
        <div>
          <label for="tok-name" class="apm-label">{{ t.enroll.tokenName }}</label>
          <input id="tok-name" v-model="formName" type="text" required class="apm-input" />
        </div>

        <div>
          <label for="tok-group" class="apm-label">{{ t.enroll.defaultGroup }}</label>
          <select id="tok-group" v-model="formGroupId" class="apm-input">
            <option value="">{{ t.enroll.noDefaultGroup }}</option>
            <option v-for="grp in deviceGroups" :key="grp.id" :value="grp.id">{{ grp.name }}</option>
          </select>
        </div>

        <div>
          <label for="tok-exp" class="apm-label">{{ t.enroll.expiresIn }}</label>
          <select id="tok-exp" v-model.number="formExpiresHours" class="apm-input">
            <option :value="24">24 h (1 Tag / Day)</option>
            <option :value="168">168 h (7 Tage / Days)</option>
            <option :value="720">720 h (30 Tage / Days)</option>
            <option :value="2160">2160 h (90 Tage / Days)</option>
          </select>
        </div>

        <div>
          <label for="tok-uses" class="apm-label">{{ t.enroll.maxUses }}</label>
          <div class="flex gap-2">
            <input
              id="tok-uses"
              v-model.number="formMaxUses"
              type="number"
              min="1"
              max="10000"
              required
              class="apm-input"
            />
            <button type="submit" class="apm-btn-primary shrink-0" :disabled="creating || !formName.trim()">
              <Plus class="h-4 w-4" aria-hidden="true" />
              <span>{{ t.app.create }}</span>
            </button>
          </div>
        </div>
      </form>

      <!-- Newly Created Secret Token Banner -->
      <div
        v-if="createdToken?.plainToken"
        role="status"
        class="mt-4 rounded-lg border border-emerald-300 bg-emerald-50 p-4"
      >
        <div class="flex items-center gap-2 text-xs font-semibold text-emerald-900">
          <KeyRound class="h-4 w-4 text-emerald-700" aria-hidden="true" />
          <span>{{ t.enroll.newTokenAlert }}</span>
        </div>
        <div class="mt-2 flex flex-wrap items-center gap-2">
          <code class="rounded border border-emerald-200 bg-white px-3 py-1.5 font-mono text-xs font-semibold text-slate-900">
            {{ createdToken.plainToken }}
          </code>
          <button type="button" class="apm-btn-secondary py-1 px-2.5 text-xs" @click="copyPlainToken">
            <Check v-if="copiedPlain" class="h-3.5 w-3.5 text-emerald-600" />
            <Copy v-else class="h-3.5 w-3.5" />
            <span>{{ copiedPlain ? t.app.copied : t.app.copy }}</span>
          </button>
        </div>
      </div>
    </section>

    <!-- Rollout Commands -->
    <RolloutCommandsCard
      :commands="createdToken?.installCommands"
      :plain-token="createdToken?.plainToken"
    />

    <!-- Existing Tokens Table -->
    <section class="apm-card overflow-x-auto">
      <div class="border-b border-slate-200 px-5 py-3.5">
        <h2 class="text-sm font-semibold text-slate-900">{{ t.enroll.activeTokens }}</h2>
      </div>

      <div v-if="!loading && tokens.length === 0" class="py-10 text-center text-sm text-slate-500">
        {{ t.enroll.emptyTokens }}
      </div>

      <table v-else class="min-w-full divide-y divide-slate-200 text-left text-sm">
        <thead class="bg-slate-50 text-xs font-semibold uppercase tracking-wide text-slate-600">
          <tr>
            <th class="px-4 py-3">{{ t.enroll.tokenName }}</th>
            <th class="px-4 py-3">{{ t.enroll.colPrefix }}</th>
            <th class="px-4 py-3">{{ t.enroll.defaultGroup }}</th>
            <th class="px-4 py-3">{{ t.enroll.colUsage }}</th>
            <th class="px-4 py-3">{{ t.enroll.colExpires }}</th>
            <th class="px-4 py-3 text-right">{{ t.app.actions }}</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-100 bg-white">
          <tr v-for="tok in tokens" :key="tok.id" class="hover:bg-slate-50/70">
            <td class="px-4 py-3 font-medium text-slate-900">{{ tok.name }}</td>
            <td class="px-4 py-3 font-mono text-xs text-slate-600">{{ tok.tokenPrefix }}…</td>
            <td class="px-4 py-3 text-xs text-slate-700">{{ tok.defaultDeviceGroupName || '—' }}</td>
            <td class="px-4 py-3 text-xs font-medium text-slate-700">{{ tok.useCount }} / {{ tok.maxUses }}</td>
            <td class="px-4 py-3 text-xs text-slate-600">{{ formatDateTime(tok.expiresAt) }}</td>
            <td class="px-4 py-3 text-right">
              <button
                type="button"
                class="rounded p-1.5 text-slate-400 hover:bg-rose-50 hover:text-rose-700"
                :aria-label="t.app.delete"
                @click="revokeToken(tok)"
              >
                <Trash2 class="h-4 w-4" />
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </section>
  </div>
</template>
