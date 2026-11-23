import type { MergeStrategy, OsFamily, PolicyCategory, PolicyRule, RuleType } from './rules'

export interface ApiErrorBody {
  error: {
    code: string
    message: string
    details: unknown
  }
}

export interface PaginationMeta {
  page: number
  pageSize: number
  totalItems: number
  totalPages: number
}

export interface PaginatedResponse<T> {
  data: T[]
  pagination: PaginationMeta
}

export interface HealthResponse {
  status: string
  version: string
  ldapMode: 'ldapproxy' | 'mock' | string
  ldapDomain: string
}

export type AuthSource = 'LDAP' | 'BOOTSTRAP'

export interface AuthUser {
  username: string
  displayName: string
  groups: string[]
  authSource: AuthSource
  ldapDomain?: string
}

export interface LoginRequest {
  username: string
  password: string
}

export interface LoginResponse {
  accessToken: string
  expiresIn: number
  user: AuthUser
}

export interface DirectoryUser {
  username: string
  displayName: string
  email: string
  dn: string
  groups: string[]
}

export interface DirectoryGroup {
  name: string
  description: string
  dn: string
  memberCount: number
}

export type ComplianceStatus = 'COMPLIANT' | 'DEGRADED' | 'ERROR' | 'OFFLINE' | 'PENDING'

export interface DashboardEvent {
  id: string
  timestamp: string
  deviceHostname: string
  status: ComplianceStatus
  message: string
}

export interface DashboardSummary {
  totalDevices: number
  compliantDevices: number
  degradedDevices: number
  errorDevices: number
  offlineDevices: number
  activePolicies: number
  activeAssignments: number
  deviceByOs: Record<OsFamily, number>
  ldapDomain: string
  ldapSchema: 'ad' | 'rfc2307' | string
  recentEvents: DashboardEvent[]
}

export interface SchemaRuleDescriptor {
  ruleType: RuleType
  category: PolicyCategory
  defaultMergeStrategy: MergeStrategy
  supportedPlatforms: OsFamily[]
  schemaVersion: number
  description?: string
}

export interface DeliveryAdapterDescriptor {
  id: string
  name: string
  status: 'ACTIVE' | 'PLANNED_V2' | string
  description?: string
}

export interface SchemaCatalogResponse {
  rules: SchemaRuleDescriptor[]
  deliveryAdapters: DeliveryAdapterDescriptor[]
}

export interface Policy {
  id: string
  name: string
  description: string
  isEnabled: boolean
  revision: number
  rules: PolicyRule[]
  createdAt: string
  updatedAt: string
}

export interface PolicyInput {
  name: string
  description: string
  isEnabled: boolean
  rules: PolicyRule[]
}

export type PolicyPatchInput = Partial<PolicyInput>

export type TargetUserType = 'ALL' | 'USER' | 'GROUP'
export type TargetDeviceType = 'ALL' | 'DEVICE' | 'DEVICE_GROUP'

export interface Assignment {
  id: string
  policyId: string
  policyName: string
  priority: number
  isEnabled: boolean
  targetUserType: TargetUserType
  targetUserRef: string | null
  targetDeviceType: TargetDeviceType
  targetDeviceRef: string | null
  targetDeviceGroupName?: string | null
  osFilter: OsFamily[]
  createdAt: string
  updatedAt: string
}

export interface AssignmentInput {
  policyId: string
  priority: number
  isEnabled: boolean
  targetUserType: TargetUserType
  targetUserRef: string | null
  targetDeviceType: TargetDeviceType
  targetDeviceRef: string | null
  osFilter: OsFamily[]
}

export type AssignmentPatchInput = Partial<AssignmentInput>

export interface ReorderAssignmentsInput {
  orderedAssignmentIds: string[]
}

export interface DeviceGroup {
  id: string
  name: string
  description: string
  tags: string[]
  deviceCount?: number
  createdAt?: string
  updatedAt?: string
}

export interface DeviceGroupInput {
  name: string
  description: string
  tags: string[]
}

export type ComplianceItemStatus = 'APPLIED' | 'SKIPPED_UNSUPPORTED' | 'FAILED'
export type ComplianceItemAction = 'ENFORCED' | 'ROLLED_BACK'

export interface DeviceComplianceItem {
  ruleType: string
  action?: ComplianceItemAction
  status: ComplianceItemStatus
  message: string
}

export interface Device {
  id: string
  hostname: string
  osFamily: OsFamily
  osVersion: string
  arch: string
  agentVersion: string
  currentUser: string | null
  deviceGroupIds: string[]
  deviceGroupNames: string[]
  appliedRevision: number
  complianceStatus: ComplianceStatus
  lastSeenAt: string | null
  complianceItems: DeviceComplianceItem[]
  createdAt: string
}

export interface DevicePatchInput {
  deviceGroupIds: string[]
}

export interface SimulatorEvaluateRequest {
  username: string
  deviceId?: string | null
  osFamilyOverride?: OsFamily | null
  deviceGroupIds?: string[]
}

export interface ShadowedPolicyTrace {
  policyId: string
  policyName: string
  priority: number
  action: 'OVERRIDDEN' | 'MERGED' | string
}

export interface RuleResolutionTrace {
  ruleType: RuleType
  category: PolicyCategory
  winningPolicyId: string
  winningPolicyName: string
  winningAssignmentId: string
  winningPriority: number
  mergeStrategy: MergeStrategy
  shadowedPolicies: ShadowedPolicyTrace[]
}

export interface SimulatorDeviceContext {
  id: string
  hostname: string
  osFamily: OsFamily
  deviceGroupNames: string[]
}

export interface SimulatorEvaluateResponse {
  username: string
  resolvedUserGroups: string[]
  device: SimulatorDeviceContext
  effectiveRules: PolicyRule[]
  trace: RuleResolutionTrace[]
}

export interface InstallCommands {
  windowsPowershell: string
  linuxBash: string
  macosZsh: string
}

export interface EnrollmentToken {
  id: string
  name: string
  plainToken?: string
  tokenPrefix: string
  defaultDeviceGroupId: string | null
  defaultDeviceGroupName: string | null
  expiresAt: string
  maxUses: number
  useCount: number
  installCommands?: InstallCommands
  createdAt?: string
}

export interface EnrollmentTokenCreateInput {
  name: string
  defaultDeviceGroupId: string | null
  expiresInHours: number
  maxUses: number
}
