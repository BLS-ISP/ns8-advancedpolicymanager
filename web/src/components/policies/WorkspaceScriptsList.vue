<script setup lang="ts">
import { Plus, Trash2 } from 'lucide-vue-next'
import type { ScriptConfigItem } from '@/api'
import { makeItemId } from './useRuleAccessor'
import { useI18n } from '@/i18n'

const props = defineProps<{
  scripts: ScriptConfigItem[]
}>()

const emit = defineEmits<{
  (e: 'update:scripts', value: ScriptConfigItem[]): void
}>()

const { t, locale } = useI18n()

function addScript() {
  const next: ScriptConfigItem = {
    id: makeItemId('scr'),
    name: locale.value === 'de' ? 'Arbeitsplatz-Initialisierung' : 'Workstation Init',
    trigger: 'LOGON',
    runAs: 'USER',
    timeoutSeconds: 60,
    windowsPowershell: "Write-Output 'Ready'",
    linuxBash: "echo 'Ready'",
    macosZsh: "echo 'Ready'"
  }
  emit('update:scripts', [...props.scripts, next])
}

function patchScript(id: string, patch: Partial<ScriptConfigItem>) {
  emit(
    'update:scripts',
    props.scripts.map((s) => (s.id === id ? { ...s, ...patch } : s))
  )
}

function removeScript(id: string) {
  emit(
    'update:scripts',
    props.scripts.filter((s) => s.id !== id)
  )
}
</script>

<template>
  <div class="space-y-3">
    <div
      v-for="scr in scripts"
      :key="scr.id"
      class="space-y-3 rounded-md border border-slate-200 bg-slate-50 p-3.5"
    >
      <div class="grid grid-cols-1 gap-3 sm:grid-cols-5">
        <div class="sm:col-span-2">
          <label class="apm-label">{{ locale === 'de' ? 'Skriptname' : 'Script Name' }}</label>
          <input
            type="text"
            class="apm-input"
            :value="scr.name"
            @input="patchScript(scr.id, { name: ($event.target as HTMLInputElement).value })"
          />
        </div>
        <div>
          <label class="apm-label">{{ locale === 'de' ? 'Zeitpunkt' : 'Trigger' }}</label>
          <select
            class="apm-input"
            :value="scr.trigger"
            @change="patchScript(scr.id, { trigger: ($event.target as HTMLSelectElement).value as 'LOGON' | 'STARTUP' })"
          >
            <option value="LOGON">{{ locale === 'de' ? 'Bei Anmeldung (LOGON)' : 'At Logon (LOGON)' }}</option>
            <option value="STARTUP">{{ locale === 'de' ? 'Beim Systemstart (STARTUP)' : 'At Boot (STARTUP)' }}</option>
          </select>
        </div>
        <div>
          <label class="apm-label">{{ locale === 'de' ? 'Kontext' : 'Run As' }}</label>
          <select
            class="apm-input"
            :value="scr.runAs"
            @change="patchScript(scr.id, { runAs: ($event.target as HTMLSelectElement).value as 'USER' | 'SYSTEM' })"
          >
            <option value="USER">{{ locale === 'de' ? 'Benutzer (USER)' : 'User (USER)' }}</option>
            <option value="SYSTEM">{{ locale === 'de' ? 'System / Root (SYSTEM)' : 'System / Root (SYSTEM)' }}</option>
          </select>
        </div>
        <div class="flex items-end gap-2">
          <div class="flex-1">
            <label class="apm-label">Timeout (s)</label>
            <input
              type="number"
              min="5"
              max="600"
              class="apm-input"
              :value="scr.timeoutSeconds"
              @input="patchScript(scr.id, { timeoutSeconds: Number(($event.target as HTMLInputElement).value) || 60 })"
            />
          </div>
          <button
            type="button"
            class="mb-0.5 rounded p-1.5 text-slate-400 hover:bg-rose-50 hover:text-rose-700"
            :aria-label="t.app.delete"
            @click="removeScript(scr.id)"
          >
            <Trash2 class="h-4 w-4" />
          </button>
        </div>
      </div>

      <div class="grid grid-cols-1 gap-3 lg:grid-cols-3">
        <div>
          <label class="apm-label">Windows PowerShell</label>
          <textarea
            rows="2"
            class="apm-input font-mono text-xs"
            :value="scr.windowsPowershell"
            @input="patchScript(scr.id, { windowsPowershell: ($event.target as HTMLTextAreaElement).value })"
          />
        </div>
        <div>
          <label class="apm-label">Linux Bash</label>
          <textarea
            rows="2"
            class="apm-input font-mono text-xs"
            :value="scr.linuxBash"
            @input="patchScript(scr.id, { linuxBash: ($event.target as HTMLTextAreaElement).value })"
          />
        </div>
        <div>
          <label class="apm-label">macOS Zsh</label>
          <textarea
            rows="2"
            class="apm-input font-mono text-xs"
            :value="scr.macosZsh"
            @input="patchScript(scr.id, { macosZsh: ($event.target as HTMLTextAreaElement).value })"
          />
        </div>
      </div>
    </div>

    <button type="button" class="apm-btn-secondary text-xs" @click="addScript">
      <Plus class="h-3.5 w-3.5" />
      <span>{{ locale === 'de' ? 'Skript hinzufügen' : 'Add script' }}</span>
    </button>
  </div>
</template>
