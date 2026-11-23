<script setup lang="ts">
import { ref } from 'vue'
import { Edit2, FolderKanban, Plus, Tag, Trash2 } from 'lucide-vue-next'
import { api, type DeviceGroup } from '@/api'
import ModalDialog from '@/components/common/ModalDialog.vue'
import { useI18n } from '@/i18n'

defineProps<{
  groups: DeviceGroup[]
}>()

const emit = defineEmits<{
  (e: 'changed'): void
  (e: 'filter-group', groupId: string): void
}>()

const { t } = useI18n()

const modalOpen = ref(false)
const editingGroup = ref<DeviceGroup | null>(null)
const name = ref('')
const description = ref('')
const tagsText = ref('')
const saving = ref(false)
const error = ref<string | null>(null)

function openCreate() {
  editingGroup.value = null
  name.value = ''
  description.value = ''
  tagsText.value = ''
  error.value = null
  modalOpen.value = true
}

function openEdit(group: DeviceGroup) {
  editingGroup.value = group
  name.value = group.name
  description.value = group.description
  tagsText.value = group.tags.join(', ')
  error.value = null
  modalOpen.value = true
}

async function saveGroup() {
  if (!name.value.trim()) return
  saving.value = true
  error.value = null
  const tags = tagsText.value
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)

  try {
    if (editingGroup.value) {
      await api.deviceGroups.update(editingGroup.value.id, {
        name: name.value.trim(),
        description: description.value.trim(),
        tags
      })
    } else {
      await api.deviceGroups.create({
        name: name.value.trim(),
        description: description.value.trim(),
        tags
      })
    }
    modalOpen.value = false
    emit('changed')
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Failed to save device group'
  } finally {
    saving.value = false
  }
}

async function deleteGroup(group: DeviceGroup) {
  if (!window.confirm(t.value.devices.confirmDeleteGroup)) return
  await api.deviceGroups.remove(group.id)
  emit('changed')
}
</script>

<template>
  <div class="space-y-4">
    <div class="flex justify-end">
      <button type="button" class="apm-btn-primary" @click="openCreate">
        <Plus class="h-4 w-4" aria-hidden="true" />
        <span>{{ t.devices.newGroup }}</span>
      </button>
    </div>

    <div class="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
      <div
        v-for="grp in groups"
        :key="grp.id"
        class="apm-card flex flex-col justify-between p-4"
      >
        <div>
          <div class="flex items-start justify-between gap-2">
            <button
              type="button"
              class="flex items-center gap-2 text-left text-sm font-semibold text-slate-900 hover:text-blue-700"
              @click="emit('filter-group', grp.id)"
            >
              <FolderKanban class="h-4 w-4 text-blue-600" aria-hidden="true" />
              <span>{{ grp.name }}</span>
            </button>
            <div class="flex items-center gap-1">
              <button
                type="button"
                class="rounded p-1 text-slate-500 hover:bg-slate-100 hover:text-slate-800"
                :aria-label="t.app.edit"
                @click="openEdit(grp)"
              >
                <Edit2 class="h-3.5 w-3.5" />
              </button>
              <button
                type="button"
                class="rounded p-1 text-slate-500 hover:bg-rose-50 hover:text-rose-700"
                :aria-label="t.app.delete"
                @click="deleteGroup(grp)"
              >
                <Trash2 class="h-3.5 w-3.5" />
              </button>
            </div>
          </div>

          <p v-if="grp.description" class="mt-1 text-xs text-slate-600">{{ grp.description }}</p>

          <div v-if="grp.tags.length" class="mt-3 flex flex-wrap gap-1.5">
            <span
              v-for="tag in grp.tags"
              :key="tag"
              class="inline-flex items-center gap-1 rounded bg-slate-100 px-2 py-0.5 text-[11px] font-medium text-slate-700"
            >
              <Tag class="h-2.5 w-2.5 text-slate-500" aria-hidden="true" />
              <span>{{ tag }}</span>
            </span>
          </div>
        </div>
      </div>
    </div>

    <ModalDialog
      :open="modalOpen"
      :title="editingGroup ? t.devices.editGroup : t.devices.newGroup"
      max-width-class="max-w-lg"
      @close="modalOpen = false"
    >
      <form id="device-group-form" class="space-y-4" @submit.prevent="saveGroup">
        <p v-if="error" role="alert" class="rounded bg-rose-50 p-2.5 text-xs text-rose-700">{{ error }}</p>
        <div>
          <label for="grp-name" class="apm-label">{{ t.devices.groupName }}</label>
          <input id="grp-name" v-model="name" type="text" required class="apm-input" />
        </div>
        <div>
          <label for="grp-desc" class="apm-label">{{ t.devices.groupDesc }}</label>
          <input id="grp-desc" v-model="description" type="text" class="apm-input" />
        </div>
        <div>
          <label for="grp-tags" class="apm-label">{{ t.devices.groupTags }}</label>
          <input id="grp-tags" v-model="tagsText" type="text" class="apm-input" placeholder="office, finance" />
        </div>
      </form>
      <template #footer>
        <button type="button" class="apm-btn-secondary" @click="modalOpen = false">{{ t.app.cancel }}</button>
        <button type="submit" form="device-group-form" class="apm-btn-primary" :disabled="saving || !name.trim()">
          {{ saving ? t.app.saving : t.app.save }}
        </button>
      </template>
    </ModalDialog>
  </div>
</template>
