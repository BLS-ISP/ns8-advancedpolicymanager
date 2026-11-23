import { computed, ref } from 'vue'
import { de, type TranslationSchema } from './de'
import { en } from './en'

export type Locale = 'de' | 'en'

const LOCALE_STORAGE_KEY = 'apm_locale'

function readInitialLocale(): Locale {
  const saved = localStorage.getItem(LOCALE_STORAGE_KEY)
  if (saved === 'en' || saved === 'de') {
    return saved
  }
  return 'de'
}

const currentLocale = ref<Locale>(readInitialLocale())

if (typeof document !== 'undefined') {
  document.documentElement.lang = currentLocale.value
}

const dictionaries: Record<Locale, TranslationSchema> = { de, en }

export function useI18n() {
  const t = computed<TranslationSchema>(() => dictionaries[currentLocale.value])

  function setLocale(next: Locale): void {
    currentLocale.value = next
    localStorage.setItem(LOCALE_STORAGE_KEY, next)
    if (typeof document !== 'undefined') {
      document.documentElement.lang = next
    }
  }

  function formatDateTime(iso: string | null | undefined): string {
    if (!iso) return '—'
    const d = new Date(iso)
    if (Number.isNaN(d.getTime())) return iso
    return new Intl.DateTimeFormat(currentLocale.value === 'de' ? 'de-DE' : 'en-US', {
      dateStyle: 'medium',
      timeStyle: 'short'
    }).format(d)
  }

  return {
    locale: currentLocale,
    t,
    setLocale,
    formatDateTime
  }
}
