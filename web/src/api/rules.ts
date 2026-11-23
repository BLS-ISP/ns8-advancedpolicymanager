export type OsFamily = 'WINDOWS' | 'LINUX' | 'MACOS'

export type PolicyCategory =
  | 'ACCESS'
  | 'WORKSPACE'
  | 'SECURITY'
  | 'DESKTOP'
  | 'CUSTOM_FINETUNING'

export type MergeStrategy = 'OVERRIDE' | 'APPEND_UNIQUE'

export interface LoginAccessConfig {
  mode: 'ALLOW_ALL' | 'ALLOW_LIST'
  allowedGroups: string[]
  allowedUsers: string[]
  denyGroups: string[]
}

export interface LocalAdminsConfig {
  adminGroups: string[]
  adminUsers: string[]
  passwordlessSudo: boolean
}

export interface NetworkShareMount {
  id: string
  name: string
  protocol: 'SMB' | 'NFS'
  remotePath: string
  windowsDriveLetter: string
  unixMountPath: string
  reconnectAtLogon: boolean
}

export interface NetworkSharesConfig {
  mounts: NetworkShareMount[]
}

export interface PrinterConfigItem {
  id: string
  name: string
  uri: string
  isDefault: boolean
  driverModel: string
}

export interface PrintersConfig {
  printers: PrinterConfigItem[]
}

export interface ScriptConfigItem {
  id: string
  name: string
  trigger: 'LOGON' | 'STARTUP'
  runAs: 'USER' | 'SYSTEM'
  timeoutSeconds: number
  windowsPowershell: string
  linuxBash: string
  macosZsh: string
}

export interface ScriptsConfig {
  scripts: ScriptConfigItem[]
}

export interface ScreenLockConfig {
  idleTimeoutSeconds: number
  requirePasswordOnWake: boolean
  lockDelaySeconds: number
}

export interface UsbStorageConfig {
  mode: 'ALLOW' | 'READ_ONLY' | 'BLOCK'
}

export interface FirewallConfig {
  isEnabled: boolean
  defaultInbound: 'BLOCK' | 'ALLOW'
  allowStealthMode: boolean
  allowedTcpPorts: number[]
  allowedUdpPorts: number[]
}

export type BrowserTarget = 'CHROME' | 'EDGE' | 'FIREFOX'

export interface BrowserConfig {
  targets: BrowserTarget[]
  homepageUrl: string
  restoreOnStartup: 'HOMEPAGE' | 'LAST_SESSION'
  disableIncognito: boolean
  disablePasswordManager: boolean
  forceExtensions: string[]
}

export interface WallpaperConfig {
  imageUrl: string
  fitMode: 'FILL' | 'FIT' | 'CENTER'
  isLocked: boolean
}

export interface SystemRestrictionsConfig {
  disableControlPanel: boolean
  disableRegistryTools: boolean
  disableTerminalForStandardUsers: boolean
}

export interface RawSettingItem {
  id: string
  targetOs: OsFamily
  engine: 'REGISTRY' | 'DCONF' | 'PLIST' | 'SYSCTL' | 'DEFAULTS' | 'FILE' | 'COMMAND'
  path: string
  key: string
  valueType: 'STRING' | 'INT' | 'BOOL' | 'JSON' | 'DWORD'
  value: string
}

export interface RawSettingConfig {
  items: RawSettingItem[]
}

export interface RuleConfigMap {
  'access.login_access': LoginAccessConfig
  'access.local_admins': LocalAdminsConfig
  'workspace.network_shares': NetworkSharesConfig
  'workspace.printers': PrintersConfig
  'workspace.scripts': ScriptsConfig
  'security.screen_lock': ScreenLockConfig
  'security.usb_storage': UsbStorageConfig
  'security.firewall': FirewallConfig
  'desktop.browser': BrowserConfig
  'desktop.wallpaper': WallpaperConfig
  'desktop.system_restrictions': SystemRestrictionsConfig
  'custom.raw_setting': RawSettingConfig
}

export type RuleType = keyof RuleConfigMap

export interface PolicyRule<K extends RuleType = RuleType> {
  ruleId: string
  category: PolicyCategory
  ruleType: K
  schemaVersion: number
  platforms: OsFamily[]
  mergeStrategy: MergeStrategy
  config: RuleConfigMap[K]
}

export const ALL_PLATFORMS: OsFamily[] = ['WINDOWS', 'LINUX', 'MACOS']

const RULE_META: Record<RuleType, { category: PolicyCategory; mergeStrategy: MergeStrategy }> = {
  'access.login_access': { category: 'ACCESS', mergeStrategy: 'OVERRIDE' },
  'access.local_admins': { category: 'ACCESS', mergeStrategy: 'APPEND_UNIQUE' },
  'workspace.network_shares': { category: 'WORKSPACE', mergeStrategy: 'APPEND_UNIQUE' },
  'workspace.printers': { category: 'WORKSPACE', mergeStrategy: 'APPEND_UNIQUE' },
  'workspace.scripts': { category: 'WORKSPACE', mergeStrategy: 'APPEND_UNIQUE' },
  'security.screen_lock': { category: 'SECURITY', mergeStrategy: 'OVERRIDE' },
  'security.usb_storage': { category: 'SECURITY', mergeStrategy: 'OVERRIDE' },
  'security.firewall': { category: 'SECURITY', mergeStrategy: 'OVERRIDE' },
  'desktop.browser': { category: 'DESKTOP', mergeStrategy: 'OVERRIDE' },
  'desktop.wallpaper': { category: 'DESKTOP', mergeStrategy: 'OVERRIDE' },
  'desktop.system_restrictions': { category: 'DESKTOP', mergeStrategy: 'OVERRIDE' },
  'custom.raw_setting': { category: 'CUSTOM_FINETUNING', mergeStrategy: 'APPEND_UNIQUE' }
}

export function createDefaultRule<K extends RuleType>(ruleType: K): PolicyRule<K> {
  const meta = RULE_META[ruleType]
  const idSuffix = Math.random().toString(36).slice(2, 8)
  const defaults: RuleConfigMap = {
    'access.login_access': { mode: 'ALLOW_LIST', allowedGroups: [], allowedUsers: [], denyGroups: [] },
    'access.local_admins': { adminGroups: [], adminUsers: [], passwordlessSudo: false },
    'workspace.network_shares': { mounts: [] },
    'workspace.printers': { printers: [] },
    'workspace.scripts': { scripts: [] },
    'security.screen_lock': { idleTimeoutSeconds: 300, requirePasswordOnWake: true, lockDelaySeconds: 5 },
    'security.usb_storage': { mode: 'BLOCK' },
    'security.firewall': {
      isEnabled: true,
      defaultInbound: 'BLOCK',
      allowStealthMode: true,
      allowedTcpPorts: [],
      allowedUdpPorts: []
    },
    'desktop.browser': {
      targets: ['CHROME', 'EDGE', 'FIREFOX'],
      homepageUrl: 'https://intranet.firma.local',
      restoreOnStartup: 'HOMEPAGE',
      disableIncognito: true,
      disablePasswordManager: false,
      forceExtensions: []
    },
    'desktop.wallpaper': {
      imageUrl: 'https://intranet.firma.local/wallpaper.jpg',
      fitMode: 'FILL',
      isLocked: true
    },
    'desktop.system_restrictions': {
      disableControlPanel: true,
      disableRegistryTools: true,
      disableTerminalForStandardUsers: false
    },
    'custom.raw_setting': { items: [] }
  }

  return {
    ruleId: `rule-${ruleType.replace('.', '-')}-${idSuffix}`,
    category: meta.category,
    ruleType,
    schemaVersion: 1,
    platforms: [...ALL_PLATFORMS],
    mergeStrategy: meta.mergeStrategy,
    config: defaults[ruleType]
  }
}
