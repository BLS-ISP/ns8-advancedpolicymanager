import type { ApiErrorBody } from './types'

const TOKEN_STORAGE_KEY = 'apm_access_token'

export class ApiRequestError extends Error {
  readonly status: number
  readonly code: string
  readonly details: unknown

  constructor(status: number, code: string, message: string, details: unknown = null) {
    super(message)
    this.name = 'ApiRequestError'
    this.status = status
    this.code = code
    this.details = details
  }
}

let unauthorizedHandler: (() => void) | null = null

export function setUnauthorizedHandler(fn: () => void): void {
  unauthorizedHandler = fn
}

export function getAccessToken(): string | null {
  return localStorage.getItem(TOKEN_STORAGE_KEY)
}

export function setAccessToken(token: string | null): void {
  if (token) {
    localStorage.setItem(TOKEN_STORAGE_KEY, token)
  } else {
    localStorage.removeItem(TOKEN_STORAGE_KEY)
  }
}

function makeIdempotencyKey(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID()
  }
  return `idem-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`
}

export function buildQuery(params: Record<string, string | number | undefined | null>): string {
  const search = new URLSearchParams()
  for (const [key, val] of Object.entries(params)) {
    if (val !== undefined && val !== null && val !== '') {
      search.set(key, String(val))
    }
  }
  const str = search.toString()
  return str ? `?${str}` : ''
}

export async function request<T>(
  path: string,
  options: RequestInit & { idempotent?: boolean; skipAuthRedirect?: boolean } = {}
): Promise<T> {
  const headers = new Headers(options.headers)
  if (!headers.has('Accept')) {
    headers.set('Accept', 'application/json')
  }
  if (options.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }
  const token = getAccessToken()
  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`)
  }
  if (options.idempotent && !headers.has('Idempotency-Key')) {
    headers.set('Idempotency-Key', makeIdempotencyKey())
  }

  const response = await fetch(`/api/v1${path}`, {
    ...options,
    headers
  })

  if (response.status === 204) {
    return undefined as T
  }

  const contentType = response.headers.get('content-type') || ''
  const isJson = contentType.includes('application/json')

  if (!response.ok) {
    if (response.status === 401 && !options.skipAuthRedirect && unauthorizedHandler) {
      unauthorizedHandler()
    }
    if (isJson) {
      const payload = (await response.json()) as Partial<ApiErrorBody>
      if (payload?.error) {
        throw new ApiRequestError(
          response.status,
          payload.error.code || 'API_ERROR',
          payload.error.message || response.statusText,
          payload.error.details ?? null
        )
      }
    }
    const fallbackText = await response.text().catch(() => response.statusText)
    throw new ApiRequestError(response.status, 'HTTP_ERROR', fallbackText || response.statusText)
  }

  if (!isJson) {
    return (await response.text()) as unknown as T
  }
  return (await response.json()) as T
}
