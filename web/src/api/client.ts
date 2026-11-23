import { buildQuery, request } from './http'
import type { OsFamily } from './rules'
import type {
  Assignment,
  AssignmentInput,
  AssignmentPatchInput,
  AuthUser,
  ComplianceStatus,
  DashboardSummary,
  Device,
  DeviceGroup,
  DeviceGroupInput,
  DevicePatchInput,
  DirectoryGroup,
  DirectoryUser,
  EnrollmentToken,
  EnrollmentTokenCreateInput,
  HealthResponse,
  LoginRequest,
  LoginResponse,
  PaginatedResponse,
  Policy,
  PolicyInput,
  PolicyPatchInput,
  ReorderAssignmentsInput,
  SchemaCatalogResponse,
  SimulatorEvaluateRequest,
  SimulatorEvaluateResponse
} from './types'

export { ApiRequestError, getAccessToken, setAccessToken, setUnauthorizedHandler } from './http'

export const api = {
  health: () => request<HealthResponse>('/health', { skipAuthRedirect: true }),

  auth: {
    login: (body: LoginRequest) =>
      request<LoginResponse>('/auth/login', {
        method: 'POST',
        body: JSON.stringify(body),
        skipAuthRedirect: true
      }),
    me: () => request<AuthUser>('/auth/me'),
    logout: () => request<void>('/auth/logout', { method: 'POST', skipAuthRedirect: true })
  },

  directory: {
    listUsers: (params: { search?: string; page?: number; pageSize?: number } = {}) =>
      request<PaginatedResponse<DirectoryUser>>(
        `/directory/users${buildQuery({ page: 1, pageSize: 25, ...params })}`
      ),
    listGroups: (params: { search?: string; page?: number; pageSize?: number } = {}) =>
      request<PaginatedResponse<DirectoryGroup>>(
        `/directory/groups${buildQuery({ page: 1, pageSize: 25, ...params })}`
      )
  },

  dashboard: {
    summary: () => request<DashboardSummary>('/dashboard/summary'),
    catalog: () => request<SchemaCatalogResponse>('/schema/catalog')
  },

  policies: {
    list: (params: { search?: string; page?: number; pageSize?: number } = {}) =>
      request<PaginatedResponse<Policy>>(
        `/policies${buildQuery({ page: 1, pageSize: 25, ...params })}`
      ),
    get: (id: string) => request<Policy>(`/policies/${encodeURIComponent(id)}`),
    create: (body: PolicyInput) =>
      request<Policy>('/policies', {
        method: 'POST',
        body: JSON.stringify(body),
        idempotent: true
      }),
    update: (id: string, body: PolicyPatchInput) =>
      request<Policy>(`/policies/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        body: JSON.stringify(body)
      }),
    remove: (id: string) =>
      request<void>(`/policies/${encodeURIComponent(id)}`, { method: 'DELETE' })
  },

  assignments: {
    list: (params: { page?: number; pageSize?: number } = {}) =>
      request<PaginatedResponse<Assignment>>(
        `/assignments${buildQuery({ page: 1, pageSize: 50, ...params })}`
      ),
    create: (body: AssignmentInput) =>
      request<Assignment>('/assignments', {
        method: 'POST',
        body: JSON.stringify(body),
        idempotent: true
      }),
    update: (id: string, body: AssignmentPatchInput) =>
      request<Assignment>(`/assignments/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        body: JSON.stringify(body)
      }),
    reorder: (body: ReorderAssignmentsInput) =>
      request<unknown>('/assignments/reorder', {
        method: 'POST',
        body: JSON.stringify(body)
      }),
    remove: (id: string) =>
      request<void>(`/assignments/${encodeURIComponent(id)}`, { method: 'DELETE' })
  },

  deviceGroups: {
    list: (params: { search?: string; page?: number; pageSize?: number } = {}) =>
      request<PaginatedResponse<DeviceGroup>>(
        `/device-groups${buildQuery({ page: 1, pageSize: 50, ...params })}`
      ),
    create: (body: DeviceGroupInput) =>
      request<DeviceGroup>('/device-groups', {
        method: 'POST',
        body: JSON.stringify(body)
      }),
    update: (id: string, body: Partial<DeviceGroupInput>) =>
      request<DeviceGroup>(`/device-groups/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        body: JSON.stringify(body)
      }),
    remove: (id: string) =>
      request<void>(`/device-groups/${encodeURIComponent(id)}`, { method: 'DELETE' })
  },

  devices: {
    list: (
      params: {
        search?: string
        osFamily?: OsFamily | ''
        complianceStatus?: ComplianceStatus | ''
        deviceGroupId?: string
        page?: number
        pageSize?: number
      } = {}
    ) =>
      request<PaginatedResponse<Device>>(
        `/devices${buildQuery({ page: 1, pageSize: 25, ...params })}`
      ),
    get: (id: string) => request<Device>(`/devices/${encodeURIComponent(id)}`),
    update: (id: string, body: DevicePatchInput) =>
      request<Device>(`/devices/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        body: JSON.stringify(body)
      }),
    remove: (id: string) =>
      request<void>(`/devices/${encodeURIComponent(id)}`, { method: 'DELETE' })
  },

  simulator: {
    evaluate: (body: SimulatorEvaluateRequest) =>
      request<SimulatorEvaluateResponse>('/simulator/evaluate', {
        method: 'POST',
        body: JSON.stringify(body)
      })
  },

  enrollmentTokens: {
    list: (params: { page?: number; pageSize?: number } = {}) =>
      request<PaginatedResponse<EnrollmentToken>>(
        `/enrollment-tokens${buildQuery({ page: 1, pageSize: 25, ...params })}`
      ),
    create: (body: EnrollmentTokenCreateInput) =>
      request<EnrollmentToken>('/enrollment-tokens', {
        method: 'POST',
        body: JSON.stringify(body),
        idempotent: true
      }),
    remove: (id: string) =>
      request<void>(`/enrollment-tokens/${encodeURIComponent(id)}`, { method: 'DELETE' })
  },

  installers: {
    getScript: (scriptName: 'install.ps1' | 'install-linux.sh' | 'install-macos.sh') =>
      request<string>(`/installers/${scriptName}`, {
        headers: { Accept: 'text/plain' }
      })
  }
}
