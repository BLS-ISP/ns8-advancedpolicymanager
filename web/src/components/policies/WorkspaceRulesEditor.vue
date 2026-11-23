<script setup lang="ts">
import { computed } from 'vue'
import { Plus, Trash2 } from 'lucide-vue-next'
import { ALL_PLATFORMS, type PolicyRule, type PrinterConfigItem } from '@/api'
import RuleCardShell from './RuleCardShell.vue'
import WorkspaceScriptsList from './WorkspaceScriptsList.vue'
import WorkspaceSharesList from './WorkspaceSharesList.vue'
import { findRule, makeItemId, toggleRuleInList, updateRuleConfig, updateRuleMeta } from './useRuleAccessor'
import { useI18n } from '@/i18n'

const props = defineProps<{
  rules: PolicyRule[]
}>()

const emit = defineEmits<{
  (e: 'update:rules', value: PolicyRule[]): void
}>()

const { t, locale } = useI18n()

const sharesRule = computed(() => findRule(props.rules, 'workspace.network_shares'))
const printersRule = computed(() => findRule(props.rules, 'workspace.printers'))
const scriptsRule = computed(() => findRule(props.rules, 'workspace.scripts'))

function addPrinter() {
  const curr = printersRule.value?.config.printers ?? []
  const next: PrinterConfigItem = {
    id: makeItemId('prn'),
    name: 'Buerodrucker-OG1',
    uri: 'ipp://print.firma.local/ipp/og1',
    isDefault: curr.length === 0,
    driverModel: 'everywhere'
  }
  emit('update:rules', updateRuleConfig(props.rules, 'workspace.printers', { printers: [...curr, next] }))
}

function patchPrinter(id: string, patch: Partial<PrinterConfigItem>) {
  const curr = printersRule.value?.config.printers ?? []
  emit(
    'update:rules',
    updateRuleConfig(props.rules, 'workspace.printers', {
      printers: curr.map((p) => (p.id === id ? { ...p, ...patch } : p))
    })
  )
}

function removePrinter(id: string) {
  const curr = printersRule.value?.config.printers ?? []
  emit(
    'update:rules',
    updateRuleConfig(props.rules, 'workspace.printers', {
      printers: curr.filter((p) => p.id !== id)
    })
  )
}
</script>

<template>
  <div class="space-y-4">
    <!-- 3. workspace.network_shares -->
    <RuleCardShell
      :title="t.ruleNames['workspace.network_shares']"
      :description="
        locale === 'de'
          ? 'Bindet SMB- oder NFS-Freigaben unter Windows als Laufwerksbuchstabe und unter Linux/macOS als Mountpfad ein.'
          : 'Maps SMB or NFS shares as Windows drive letters and Linux/macOS mount directories.'
      "
      :enabled="Boolean(sharesRule)"
      :platforms="sharesRule?.platforms ?? ALL_PLATFORMS"
      :merge-strategy="sharesRule?.mergeStrategy ?? 'APPEND_UNIQUE'"
      @update:enabled="emit('update:rules', toggleRuleInList(rules, 'workspace.network_shares', $event))"
      @update:platforms="emit('update:rules', updateRuleMeta(rules, 'workspace.network_shares', { platforms: $event }))"
      @update:merge-strategy="emit('update:rules', updateRuleMeta(rules, 'workspace.network_shares', { mergeStrategy: $event }))"
    >
      <WorkspaceSharesList
        v-if="sharesRule"
        :mounts="sharesRule.config.mounts"
        @update:mounts="emit('update:rules', updateRuleConfig(rules, 'workspace.network_shares', { mounts: $event }))"
      />
    </RuleCardShell>

    <!-- 4. workspace.printers -->
    <RuleCardShell
      :title="t.ruleNames['workspace.printers']"
      :description="
        locale === 'de'
          ? 'Verteilt IPP/CUPS-kompatible Netzwerkdrucker automatisch inklusive Standarddrucker-Markierung.'
          : 'Automatically provisions IPP/CUPS network printers and optional default printer selection.'
      "
      :enabled="Boolean(printersRule)"
      :platforms="printersRule?.platforms ?? ALL_PLATFORMS"
      :merge-strategy="printersRule?.mergeStrategy ?? 'APPEND_UNIQUE'"
      @update:enabled="emit('update:rules', toggleRuleInList(rules, 'workspace.printers', $event))"
      @update:platforms="emit('update:rules', updateRuleMeta(rules, 'workspace.printers', { platforms: $event }))"
      @update:merge-strategy="emit('update:rules', updateRuleMeta(rules, 'workspace.printers', { mergeStrategy: $event }))"
    >
      <div v-if="printersRule" class="space-y-3">
        <div
          v-for="prn in printersRule.config.printers"
          :key="prn.id"
          class="grid grid-cols-1 gap-2.5 rounded-md border border-slate-200 bg-slate-50 p-3 sm:grid-cols-5"
        >
          <input
            type="text"
            class="apm-input text-xs"
            placeholder="Printer Name"
            :value="prn.name"
            @input="patchPrinter(prn.id, { name: ($event.target as HTMLInputElement).value })"
          />
          <input
            type="text"
            class="apm-input font-mono text-xs sm:col-span-2"
            placeholder="ipp://print.firma.local/ipp/og1"
            :value="prn.uri"
            @input="patchPrinter(prn.id, { uri: ($event.target as HTMLInputElement).value })"
          />
          <input
            type="text"
            class="apm-input font-mono text-xs"
            placeholder="everywhere"
            :value="prn.driverModel"
            @input="patchPrinter(prn.id, { driverModel: ($event.target as HTMLInputElement).value })"
          />
          <div class="flex items-center justify-between gap-2 text-xs">
            <label class="inline-flex cursor-pointer items-center gap-1.5">
              <input
                type="checkbox"
                class="h-4 w-4 rounded border-slate-300 text-blue-600"
                :checked="prn.isDefault"
                @change="patchPrinter(prn.id, { isDefault: ($event.target as HTMLInputElement).checked })"
              />
              <span>{{ locale === 'de' ? 'Standard' : 'Default' }}</span>
            </label>
            <button
              type="button"
              class="rounded p-1.5 text-slate-400 hover:bg-rose-50 hover:text-rose-700"
              :aria-label="t.app.delete"
              @click="removePrinter(prn.id)"
            >
              <Trash2 class="h-4 w-4" />
            </button>
          </div>
        </div>

        <button type="button" class="apm-btn-secondary text-xs" @click="addPrinter">
          <Plus class="h-3.5 w-3.5" />
          <span>{{ locale === 'de' ? 'Drucker hinzufügen' : 'Add printer' }}</span>
        </button>
      </div>
    </RuleCardShell>

    <!-- 5. workspace.scripts -->
    <RuleCardShell
      :title="t.ruleNames['workspace.scripts']"
      :description="
        locale === 'de'
          ? 'Führt benutzerdefinierte PowerShell-, Bash- oder Zsh-Skripte beim Systemstart oder bei der Anmeldung aus.'
          : 'Executes custom PowerShell, Bash, or Zsh scripts at system boot or user logon.'
      "
      :enabled="Boolean(scriptsRule)"
      :platforms="scriptsRule?.platforms ?? ALL_PLATFORMS"
      :merge-strategy="scriptsRule?.mergeStrategy ?? 'APPEND_UNIQUE'"
      @update:enabled="emit('update:rules', toggleRuleInList(rules, 'workspace.scripts', $event))"
      @update:platforms="emit('update:rules', updateRuleMeta(rules, 'workspace.scripts', { platforms: $event }))"
      @update:merge-strategy="emit('update:rules', updateRuleMeta(rules, 'workspace.scripts', { mergeStrategy: $event }))"
    >
      <WorkspaceScriptsList
        v-if="scriptsRule"
        :scripts="scriptsRule.config.scripts"
        @update:scripts="emit('update:rules', updateRuleConfig(rules, 'workspace.scripts', { scripts: $event }))"
      />
    </RuleCardShell>
  </div>
</template>
