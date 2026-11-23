<script setup lang="ts">
import { Plus, Trash2 } from 'lucide-vue-next'
import type { NetworkShareMount } from '@/api'
import { makeItemId } from './useRuleAccessor'
import { useI18n } from '@/i18n'

const props = defineProps<{
  mounts: NetworkShareMount[]
}>()

const emit = defineEmits<{
  (e: 'update:mounts', value: NetworkShareMount[]): void
}>()

const { t, locale } = useI18n()

function addShare() {
  const next: NetworkShareMount = {
    id: makeItemId('share'),
    name: 'Abteilung',
    protocol: 'SMB',
    remotePath: '\\\\files.firma.local\\abteilung',
    windowsDriveLetter: 'X:',
    unixMountPath: '/mnt/abteilung',
    reconnectAtLogon: true
  }
  emit('update:mounts', [...props.mounts, next])
}

function patchShare(id: string, patch: Partial<NetworkShareMount>) {
  emit(
    'update:mounts',
    props.mounts.map((m) => (m.id === id ? { ...m, ...patch } : m))
  )
}

function removeShare(id: string) {
  emit(
    'update:mounts',
    props.mounts.filter((m) => m.id !== id)
  )
}
</script>

<template>
  <div class="space-y-3">
    <div
      v-for="m in mounts"
      :key="m.id"
      class="grid grid-cols-1 gap-2.5 rounded-md border border-slate-200 bg-slate-50 p-3 sm:grid-cols-12"
    >
      <input
        type="text"
        class="apm-input text-xs sm:col-span-2"
        placeholder="Name"
        :value="m.name"
        @input="patchShare(m.id, { name: ($event.target as HTMLInputElement).value })"
      />
      <select
        class="apm-input text-xs sm:col-span-2"
        aria-label="Protocol"
        :value="m.protocol"
        @change="patchShare(m.id, { protocol: ($event.target as HTMLSelectElement).value as 'SMB' | 'NFS' })"
      >
        <option value="SMB">SMB / CIFS</option>
        <option value="NFS">NFS</option>
      </select>
      <input
        type="text"
        class="apm-input font-mono text-xs sm:col-span-4"
        placeholder="\\files.firma.local\share"
        :value="m.remotePath"
        @input="patchShare(m.id, { remotePath: ($event.target as HTMLInputElement).value })"
      />
      <input
        type="text"
        class="apm-input font-mono text-xs sm:col-span-1"
        placeholder="X:"
        :value="m.windowsDriveLetter"
        @input="patchShare(m.id, { windowsDriveLetter: ($event.target as HTMLInputElement).value })"
      />
      <div class="flex items-center gap-1.5 sm:col-span-3">
        <input
          type="text"
          class="apm-input font-mono text-xs"
          placeholder="/mnt/share"
          :value="m.unixMountPath"
          @input="patchShare(m.id, { unixMountPath: ($event.target as HTMLInputElement).value })"
        />
        <button
          type="button"
          class="shrink-0 rounded p-1.5 text-slate-400 hover:bg-rose-50 hover:text-rose-700"
          :aria-label="t.app.delete"
          @click="removeShare(m.id)"
        >
          <Trash2 class="h-4 w-4" />
        </button>
      </div>
    </div>

    <button type="button" class="apm-btn-secondary text-xs" @click="addShare">
      <Plus class="h-3.5 w-3.5" />
      <span>{{ locale === 'de' ? 'Netzlaufwerk hinzufügen' : 'Add network share' }}</span>
    </button>
  </div>
</template>
