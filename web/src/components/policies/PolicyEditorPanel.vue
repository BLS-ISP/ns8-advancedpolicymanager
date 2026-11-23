<script setup lang="ts">
import { computed, ref } from 'vue'
import { ArrowLeft, Save } from 'lucide-vue-next'
import type { PolicyCategory, PolicyInput, PolicyRule } from '@/api'
import AccessRulesEditor from './AccessRulesEditor.vue'
import CustomFinetuningEditor from './CustomFinetuningEditor.vue'
import DesktopRulesEditor from './DesktopRulesEditor.vue'
import SecurityRulesEditor from './SecurityRulesEditor.vue'
import WorkspaceRulesEditor from './WorkspaceRulesEditor.vue'
import { useI18n } from '@/i18n'

const props = defineProps<{
  initialPolicy: PolicyInput & { id?: string; revision?: number }
  saving: boolean
  error: string | null
}>()

const emit = defineEmits<{
  (e: 'cancel'): void
  (e: 'save', payload: PolicyInput): void
}>()

const { t } = useI18n()

const name = ref(props.initialPolicy.name)
const description = ref(props.initialPolicy.description)
const isEnabled = ref(props.initialPolicy.isEnabled)
const rules = ref<PolicyRule[]>(JSON.parse(JSON.stringify(props.initialPolicy.rules)) as PolicyRule[])

type TabKey = 'ACCESS' | 'WORKSPACE' | 'SECURITY' | 'DESKTOP' | 'CUSTOM_FINETUNING'
const activeTab = ref<TabKey>('SECURITY')

const tabs = computed<Array<{ key: TabKey; label: string; count: number }>>(() => {
  const countByCat = (cat: PolicyCategory) => rules.value.filter((r) => r.category === cat).length
  return [
    { key: 'ACCESS', label: t.value.policies.tabs.access, count: countByCat('ACCESS') },
    { key: 'WORKSPACE', label: t.value.policies.tabs.workspace, count: countByCat('WORKSPACE') },
    { key: 'SECURITY', label: t.value.policies.tabs.security, count: countByCat('SECURITY') },
    { key: 'DESKTOP', label: t.value.policies.tabs.desktop, count: countByCat('DESKTOP') },
    { key: 'CUSTOM_FINETUNING', label: t.value.policies.tabs.custom, count: countByCat('CUSTOM_FINETUNING') }
  ]
})

function handleSubmit() {
  if (!name.value.trim()) return
  emit('save', {
    name: name.value.trim(),
    description: description.value.trim(),
    isEnabled: isEnabled.value,
    rules: rules.value
  })
}
</script>

<template>
  <form class="space-y-5" @submit.prevent="handleSubmit">
    <!-- Top Bar -->
    <div class="flex flex-wrap items-center justify-between gap-3">
      <div class="flex items-center gap-3">
        <button type="button" class="apm-btn-secondary py-1.5 px-2.5 text-xs" @click="emit('cancel')">
          <ArrowLeft class="h-4 w-4" aria-hidden="true" />
          <span>{{ t.policies.backToList }}</span>
        </button>
        <h1 class="text-xl font-bold text-slate-900">
          {{ initialPolicy.id ? t.policies.editPolicy : t.policies.createPolicy }}
        </h1>
        <span
          v-if="initialPolicy.revision"
          class="rounded bg-slate-200 px-2 py-0.5 font-mono text-xs font-semibold text-slate-700"
        >
          Rev. {{ initialPolicy.revision }}
        </span>
      </div>

      <div class="flex items-center gap-2">
        <button type="button" class="apm-btn-secondary" @click="emit('cancel')">
          {{ t.app.cancel }}
        </button>
        <button type="submit" class="apm-btn-primary" :disabled="saving || !name.trim()">
          <Save class="h-4 w-4" aria-hidden="true" />
          <span>{{ saving ? t.app.saving : t.app.save }}</span>
        </button>
      </div>
    </div>

    <p v-if="error" role="alert" class="rounded-md border border-rose-200 bg-rose-50 p-3 text-sm text-rose-800">
      {{ error }}
    </p>

    <!-- Policy Metadata -->
    <div class="apm-card grid grid-cols-1 gap-4 p-4 md:grid-cols-12">
      <div class="md:col-span-4">
        <label for="pol-name" class="apm-label">{{ t.policies.name }}</label>
        <input id="pol-name" v-model="name" type="text" required class="apm-input" />
      </div>
      <div class="md:col-span-6">
        <label for="pol-desc" class="apm-label">{{ t.policies.description }}</label>
        <input id="pol-desc" v-model="description" type="text" class="apm-input" />
      </div>
      <div class="flex items-end pb-1.5 md:col-span-2">
        <label class="inline-flex cursor-pointer items-center gap-2 text-sm font-medium text-slate-800">
          <input v-model="isEnabled" type="checkbox" class="h-4 w-4 rounded border-slate-300 text-blue-600" />
          <span>{{ isEnabled ? t.app.enabled : t.app.disabled }}</span>
        </label>
      </div>
    </div>

    <!-- 5 Category Tabs -->
    <div class="overflow-x-auto border-b border-slate-200" role="tablist">
      <div class="flex min-w-max gap-2">
        <button
          v-for="tab in tabs"
          :key="tab.key"
          type="button"
          role="tab"
          :aria-selected="activeTab === tab.key"
          class="inline-flex items-center gap-2 border-b-2 px-3.5 py-2.5 text-sm font-semibold transition-colors"
          :class="
            activeTab === tab.key
              ? 'border-blue-600 text-blue-600'
              : 'border-transparent text-slate-600 hover:text-slate-900'
          "
          @click="activeTab = tab.key"
        >
          <span>{{ tab.label }}</span>
          <span
            v-if="tab.count > 0"
            class="rounded-full px-1.5 py-0.5 text-[11px] font-bold"
            :class="activeTab === tab.key ? 'bg-blue-100 text-blue-800' : 'bg-slate-200 text-slate-700'"
          >
            {{ tab.count }}
          </span>
        </button>
      </div>
    </div>

    <!-- Active Category Editor -->
    <AccessRulesEditor v-if="activeTab === 'ACCESS'" v-model:rules="rules" />
    <WorkspaceRulesEditor v-else-if="activeTab === 'WORKSPACE'" v-model:rules="rules" />
    <SecurityRulesEditor v-else-if="activeTab === 'SECURITY'" v-model:rules="rules" />
    <DesktopRulesEditor v-else-if="activeTab === 'DESKTOP'" v-model:rules="rules" />
    <CustomFinetuningEditor v-else v-model:rules="rules" />
  </form>
</template>
