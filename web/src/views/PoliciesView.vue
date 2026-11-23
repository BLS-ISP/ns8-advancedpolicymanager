<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Copy, Edit2, FileSliders, Plus, Search, Trash2 } from 'lucide-vue-next'
import { ALL_PLATFORMS, api, type OsFamily, type Policy, type PolicyInput } from '@/api'
import OsBadges from '@/components/common/OsBadges.vue'
import PolicyEditorPanel from '@/components/policies/PolicyEditorPanel.vue'
import { useI18n } from '@/i18n'

const route = useRoute()
const router = useRouter()
const { t, formatDateTime } = useI18n()

const policies = ref<Policy[]>([])
const search = ref('')
const loading = ref(true)
const saving = ref(false)
const listError = ref<string | null>(null)
const editorError = ref<string | null>(null)
const editingDraft = ref<(PolicyInput & { id?: string; revision?: number }) | null>(null)

async function loadPolicies() {
  loading.value = true
  listError.value = null
  try {
    const res = await api.policies.list({ search: search.value || undefined, pageSize: 50 })
    policies.value = res.data
  } catch (err) {
    listError.value = err instanceof Error ? err.message : 'Failed to load policies'
  } finally {
    loading.value = false
  }
}

onMounted(async () => {
  await loadPolicies()
  if (route.query.new === '1') {
    startCreate()
    await router.replace({ path: '/policies', query: {} })
  }
})

function startCreate() {
  editorError.value = null
  editingDraft.value = {
    name: '',
    description: '',
    isEnabled: true,
    rules: []
  }
}

function startEdit(pol: Policy) {
  editorError.value = null
  editingDraft.value = {
    id: pol.id,
    revision: pol.revision,
    name: pol.name,
    description: pol.description,
    isEnabled: pol.isEnabled,
    rules: pol.rules
  }
}

function duplicatePolicy(pol: Policy) {
  editorError.value = null
  editingDraft.value = {
    name: `${pol.name} (Copy)`,
    description: pol.description,
    isEnabled: false,
    rules: pol.rules
  }
}

async function handleSave(payload: PolicyInput) {
  saving.value = true
  editorError.value = null
  try {
    if (editingDraft.value?.id) {
      await api.policies.update(editingDraft.value.id, payload)
    } else {
      await api.policies.create(payload)
    }
    editingDraft.value = null
    await loadPolicies()
  } catch (err) {
    editorError.value = err instanceof Error ? err.message : 'Failed to save policy'
  } finally {
    saving.value = false
  }
}

async function togglePolicyEnabled(pol: Policy) {
  await api.policies.update(pol.id, { isEnabled: !pol.isEnabled })
  await loadPolicies()
}

async function deletePolicy(pol: Policy) {
  if (!window.confirm(t.value.policies.confirmDelete)) return
  await api.policies.remove(pol.id)
  await loadPolicies()
}

function policyPlatforms(pol: Policy): OsFamily[] {
  if (!pol.rules.length) return ALL_PLATFORMS
  const set = new Set<OsFamily>()
  for (const r of pol.rules) {
    for (const p of r.platforms) set.add(p)
  }
  return ALL_PLATFORMS.filter((os) => set.has(os))
}
</script>

<template>
  <PolicyEditorPanel
    v-if="editingDraft"
    :initial-policy="editingDraft"
    :saving="saving"
    :error="editorError"
    @cancel="editingDraft = null"
    @save="handleSave"
  />

  <div v-else class="space-y-5">
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div>
        <h1 class="text-2xl font-bold tracking-tight text-slate-900">{{ t.policies.title }}</h1>
        <p class="mt-1 text-sm text-slate-600">{{ t.policies.subtitle }}</p>
      </div>
      <button type="button" class="apm-btn-primary" @click="startCreate">
        <Plus class="h-4 w-4" aria-hidden="true" />
        <span>{{ t.policies.newPolicy }}</span>
      </button>
    </div>

    <p v-if="listError" role="alert" class="rounded-md border border-rose-200 bg-rose-50 p-3 text-sm text-rose-800">
      {{ listError }}
    </p>

    <div class="apm-card p-3.5">
      <div class="relative max-w-md">
        <Search class="pointer-events-none absolute left-3 top-2 h-4 w-4 text-slate-400" aria-hidden="true" />
        <input
          v-model="search"
          type="search"
          class="apm-input pl-9"
          :placeholder="t.app.search"
          :aria-label="t.app.search"
          @keydown.enter="loadPolicies"
        />
      </div>
    </div>

    <div v-if="!loading && policies.length === 0" class="apm-card py-14 text-center">
      <FileSliders class="mx-auto h-10 w-10 text-slate-400" aria-hidden="true" />
      <h2 class="mt-3 text-sm font-semibold text-slate-900">{{ t.policies.emptyTitle }}</h2>
      <p class="mt-1 text-xs text-slate-500">{{ t.policies.emptyText }}</p>
      <button type="button" class="apm-btn-primary mt-4" @click="startCreate">
        <Plus class="h-4 w-4" />
        <span>{{ t.policies.newPolicy }}</span>
      </button>
    </div>

    <div v-else class="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <article
        v-for="pol in policies"
        :key="pol.id"
        class="apm-card flex flex-col justify-between p-5 transition-colors hover:border-slate-300"
      >
        <div>
          <div class="flex items-start justify-between gap-3">
            <div>
              <button
                type="button"
                class="text-left text-base font-semibold text-slate-900 hover:text-blue-700"
                @click="startEdit(pol)"
              >
                {{ pol.name }}
              </button>
              <p v-if="pol.description" class="mt-0.5 text-xs text-slate-600">{{ pol.description }}</p>
            </div>

            <button
              type="button"
              class="rounded-full border px-2.5 py-0.5 text-xs font-medium"
              :class="
                pol.isEnabled
                  ? 'border-emerald-200 bg-emerald-50 text-emerald-800'
                  : 'border-slate-200 bg-slate-100 text-slate-600'
              "
              @click="togglePolicyEnabled(pol)"
            >
              {{ pol.isEnabled ? t.app.enabled : t.app.disabled }}
            </button>
          </div>

          <div class="mt-3 flex flex-wrap items-center gap-2">
            <OsBadges :platforms="policyPlatforms(pol)" compact />
            <span class="rounded bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-700">
              {{ pol.rules.length }} {{ t.policies.rulesCount }}
            </span>
            <span class="rounded bg-slate-100 px-2 py-0.5 font-mono text-xs text-slate-600">
              {{ t.policies.revision }} {{ pol.revision }}
            </span>
          </div>
        </div>

        <div class="mt-4 flex items-center justify-between border-t border-slate-100 pt-3 text-xs text-slate-500">
          <span>{{ formatDateTime(pol.updatedAt) }}</span>
          <div class="inline-flex items-center gap-1.5">
            <button type="button" class="apm-btn-secondary py-1 px-2.5 text-xs" @click="startEdit(pol)">
              <Edit2 class="h-3.5 w-3.5" />
              <span>{{ t.app.edit }}</span>
            </button>
            <button
              type="button"
              class="rounded p-1.5 text-slate-500 hover:bg-slate-100 hover:text-slate-900"
              title="Duplicate"
              aria-label="Duplicate policy"
              @click="duplicatePolicy(pol)"
            >
              <Copy class="h-3.5 w-3.5" />
            </button>
            <button
              type="button"
              class="rounded p-1.5 text-slate-400 hover:bg-rose-50 hover:text-rose-700"
              :aria-label="t.app.delete"
              @click="deletePolicy(pol)"
            >
              <Trash2 class="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      </article>
    </div>
  </div>
</template>
