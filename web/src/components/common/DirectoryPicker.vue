<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { Plus, Search, User, Users, X } from 'lucide-vue-next'
import { api, type DirectoryGroup, type DirectoryUser } from '@/api'

const props = defineProps<{
  kind: 'USER' | 'GROUP'
  multiple?: boolean
  modelValue?: string
  values?: string[]
  label?: string
  placeholder?: string
  inputId?: string
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', value: string): void
  (e: 'update:values', values: string[]): void
}>()

const query = ref('')
const isOpen = ref(false)
const loading = ref(false)
const users = ref<DirectoryUser[]>([])
const groups = ref<DirectoryGroup[]>([])
let debounceTimer: ReturnType<typeof setTimeout> | null = null

async function loadOptions(search: string) {
  loading.value = true
  try {
    if (props.kind === 'USER') {
      const res = await api.directory.listUsers({ search, pageSize: 50 })
      users.value = res.data
    } else {
      const res = await api.directory.listGroups({ search, pageSize: 50 })
      groups.value = res.data
    }
  } catch {
    users.value = []
    groups.value = []
  } finally {
    loading.value = false
  }
}

watch(query, (val) => {
  if (debounceTimer) clearTimeout(debounceTimer)
  debounceTimer = setTimeout(() => {
    void loadOptions(val)
  }, 180)
})

watch(
  () => props.kind,
  () => {
    void loadOptions(query.value)
  }
)

onMounted(() => {
  void loadOptions('')
})

function pickItem(identifier: string) {
  const clean = identifier.trim()
  if (!clean) return
  if (props.multiple) {
    const current = props.values ?? []
    if (!current.includes(clean)) {
      emit('update:values', [...current, clean])
    }
    query.value = ''
    isOpen.value = false
  } else {
    emit('update:modelValue', clean)
    query.value = clean
    isOpen.value = false
  }
}

function removeChip(val: string) {
  const current = props.values ?? []
  emit(
    'update:values',
    current.filter((item) => item !== val)
  )
}

function handleEnter() {
  if (query.value.trim()) {
    pickItem(query.value)
  }
}

function handleSingleInput(val: string) {
  query.value = val
  if (!props.multiple) {
    emit('update:modelValue', val)
  }
  isOpen.value = true
}

function handleBlur() {
  window.setTimeout(() => {
    isOpen.value = false
  }, 160)
}
</script>

<template>
  <div class="relative">
    <label v-if="label" :for="inputId" class="apm-label">{{ label }}</label>

    <div v-if="multiple && (values?.length ?? 0) > 0" class="mb-2 flex flex-wrap gap-1.5">
      <span
        v-for="item in values"
        :key="item"
        class="inline-flex items-center gap-1 rounded-md border border-blue-200 bg-blue-50 px-2 py-0.5 text-xs font-medium text-blue-900"
      >
        <User v-if="kind === 'USER'" class="h-3 w-3 text-blue-600" aria-hidden="true" />
        <Users v-else class="h-3 w-3 text-blue-600" aria-hidden="true" />
        <span>{{ item }}</span>
        <button
          type="button"
          class="ml-0.5 rounded text-blue-700 hover:bg-blue-100"
          :aria-label="`Remove ${item}`"
          @click="removeChip(item)"
        >
          <X class="h-3 w-3" aria-hidden="true" />
        </button>
      </span>
    </div>

    <div class="flex gap-1.5">
      <div class="relative flex-1">
        <Search class="pointer-events-none absolute left-2.5 top-2 h-4 w-4 text-slate-400" aria-hidden="true" />
        <input
          :id="inputId"
          type="text"
          class="apm-input pl-8"
          :value="multiple ? query : (modelValue ?? query)"
          :placeholder="placeholder"
          autocomplete="off"
          @focus="isOpen = true"
          @blur="handleBlur"
          @input="handleSingleInput(($event.target as HTMLInputElement).value)"
          @keydown.enter.prevent="handleEnter"
        />
      </div>
      <button
        v-if="multiple"
        type="button"
        class="apm-btn-secondary px-2.5"
        :disabled="!query.trim()"
        aria-label="Add entry"
        @click="handleEnter"
      >
        <Plus class="h-4 w-4" aria-hidden="true" />
      </button>
    </div>

    <ul
      v-if="isOpen && ((kind === 'USER' && users.length > 0) || (kind === 'GROUP' && groups.length > 0))"
      role="listbox"
      class="absolute z-30 mt-1 max-h-52 w-full overflow-y-auto rounded-md border border-slate-200 bg-white py-1 shadow-lg"
    >
      <template v-if="kind === 'USER'">
        <li v-for="u in users" :key="u.username">
          <button
            type="button"
            class="flex w-full items-center justify-between px-3 py-1.5 text-left text-xs hover:bg-slate-100"
            @mousedown.prevent="pickItem(u.username)"
          >
            <div>
              <span class="font-semibold text-slate-900">{{ u.displayName || u.username }}</span>
              <span class="ml-1.5 font-mono text-slate-500">({{ u.username }})</span>
            </div>
            <span class="truncate pl-2 text-[11px] text-slate-500">{{ u.groups.slice(0, 2).join(', ') }}</span>
          </button>
        </li>
      </template>
      <template v-else>
        <li v-for="g in groups" :key="g.name">
          <button
            type="button"
            class="flex w-full items-center justify-between px-3 py-1.5 text-left text-xs hover:bg-slate-100"
            @mousedown.prevent="pickItem(g.name)"
          >
            <div class="min-w-0 truncate">
              <span class="font-semibold text-slate-900">{{ g.name }}</span>
              <span v-if="g.description" class="ml-1.5 text-slate-500">— {{ g.description }}</span>
            </div>
            <span class="shrink-0 pl-2 text-[11px] font-medium text-slate-500">{{ g.memberCount }}</span>
          </button>
        </li>
      </template>
    </ul>
  </div>
</template>
