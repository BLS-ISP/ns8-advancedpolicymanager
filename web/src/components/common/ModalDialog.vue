<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { X } from 'lucide-vue-next'
import { useI18n } from '@/i18n'

const props = defineProps<{
  open: boolean
  title: string
  maxWidthClass?: string
}>()

const emit = defineEmits<{
  (e: 'close'): void
}>()

const { t } = useI18n()
const closeBtnRef = ref<HTMLButtonElement | null>(null)

function handleKeydown(event: KeyboardEvent) {
  if (event.key === 'Escape' && props.open) {
    emit('close')
  }
}

watch(
  () => props.open,
  async (isOpen) => {
    if (isOpen) {
      await nextTick()
      closeBtnRef.value?.focus()
    }
  }
)

onMounted(() => window.addEventListener('keydown', handleKeydown))
onBeforeUnmount(() => window.removeEventListener('keydown', handleKeydown))
</script>

<template>
  <Teleport to="body">
    <div
      v-if="open"
      class="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 p-4"
      role="dialog"
      aria-modal="true"
      :aria-label="title"
      @click.self="emit('close')"
    >
      <div
        class="flex max-h-[90vh] w-full flex-col overflow-hidden rounded-lg border border-slate-200 bg-white shadow-xl"
        :class="maxWidthClass || 'max-w-2xl'"
      >
        <div class="flex items-center justify-between border-b border-slate-200 px-5 py-3.5">
          <h2 class="text-base font-semibold text-slate-900">{{ title }}</h2>
          <button
            ref="closeBtnRef"
            type="button"
            class="rounded-md p-1 text-slate-500 hover:bg-slate-100 hover:text-slate-800"
            :aria-label="t.app.close"
            @click="emit('close')"
          >
            <X class="h-5 w-5" aria-hidden="true" />
          </button>
        </div>

        <div class="flex-1 overflow-y-auto px-5 py-4">
          <slot />
        </div>

        <div v-if="$slots.footer" class="flex items-center justify-end gap-2 border-t border-slate-200 bg-slate-50 px-5 py-3">
          <slot name="footer" />
        </div>
      </div>
    </div>
  </Teleport>
</template>
