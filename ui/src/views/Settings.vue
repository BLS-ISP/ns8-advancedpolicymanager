<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-toolbar">
        <h2>{{ $t("settings.title") }}</h2>
      </cv-column>
    </cv-row>

    <cv-row>
      <cv-column>
        <cv-tile kind="standard" :light="true" class="form-max-width">
          <cv-skeleton-text
            v-if="loading.getConfiguration"
            :paragraph="true"
            :line-count="8"
          />

          <cv-form v-else @submit.prevent="configureModule">
            <NsInlineNotification
              v-if="saveSucceeded"
              kind="success"
              :title="$t('settings.saved_title')"
              :description="$t('settings.saved_description')"
              @close="saveSucceeded = false"
              class="mg-bottom-md"
            />

            <NsInlineNotification
              v-if="error.configureModule"
              kind="error"
              :title="$t('error.cannot_configure_module')"
              :description="error.configureModule"
              :showCloseButton="false"
              class="mg-bottom-md"
            />

            <!-- FQDN -->
            <NsTextInput
              v-model.trim="form.host"
              :label="$t('settings.host')"
              :placeholder="$t('settings.host_placeholder')"
              :helper-text="$t('settings.host_helper')"
              :invalid-message="error.host"
              :disabled="loading.configureModule"
              ref="host"
              class="mg-bottom-md"
            />

            <!-- Let's Encrypt -->
            <NsToggle
              :label="$t('settings.lets_encrypt')"
              value="lets_encrypt"
              v-model="form.lets_encrypt"
              :disabled="loading.configureModule"
              class="mg-bottom-md"
            >
              <template slot="text-left">{{ $t("common.disabled") }}</template>
              <template slot="text-right">{{ $t("common.enabled") }}</template>
            </NsToggle>

            <!-- HTTP -> HTTPS -->
            <NsToggle
              :label="$t('settings.http2https')"
              value="http2https"
              v-model="form.http2https"
              :disabled="loading.configureModule"
              class="mg-bottom-md"
            >
              <template slot="text-left">{{ $t("common.disabled") }}</template>
              <template slot="text-right">{{ $t("common.enabled") }}</template>
            </NsToggle>

            <!-- NS8 User Domain Dropdown -->
            <div class="mg-bottom-md">
              <cv-select
                v-model="form.ldap_domain"
                :label="$t('settings.ldap_domain')"
                :helper-text="$t('settings.ldap_domain_helper')"
                :disabled="loading.configureModule"
                @change="onDomainChanged"
              >
                <cv-select-option value="">
                  {{ $t("settings.no_user_domain") }}
                </cv-select-option>
                <cv-select-option
                  v-for="domainOption in normalizedUserDomains"
                  :key="domainOption.value"
                  :value="domainOption.value"
                >
                  {{ domainOption.label }}
                </cv-select-option>
              </cv-select>
            </div>

            <!-- Live LDAP/AD Group Discovery & Multi-Select -->
            <div class="group-discovery-box mg-bottom-md">
              <div v-if="form.ldap_domain" class="discovery-toolbar">
                <cv-inline-loading
                  v-if="loading.listDomainGroups"
                  state="active"
                  :loading-text="
                    $t('settings.discovering_groups', {
                      domain: form.ldap_domain,
                    })
                  "
                />
                <span v-else class="discovery-status">
                  {{
                    discoveredGroups.length > 0
                      ? $t("settings.discovered_groups_count", {
                          count: discoveredGroups.length,
                          domain: form.ldap_domain,
                        })
                      : $t("settings.discovered_groups_empty", {
                          domain: form.ldap_domain,
                        })
                  }}
                </span>

                <NsButton
                  kind="ghost"
                  size="small"
                  :icon="Renew16"
                  :disabled="loading.configureModule || loading.listDomainGroups"
                  type="button"
                  @click="discoverDomainGroups(form.ldap_domain)"
                >
                  {{ $t("settings.refresh_groups") }}
                </NsButton>
              </div>

              <NsInlineNotification
                v-if="discoveryWarning"
                kind="warning"
                :title="$t('settings.discovery_warning_title')"
                :description="discoveryWarning"
                @close="discoveryWarning = ''"
                class="mg-bottom-sm"
              />

              <NsMultiSelect
                v-model="selectedAdminGroups"
                :options="adminGroupOptions"
                :title="$t('settings.admin_groups')"
                :label="$t('settings.admin_groups_placeholder')"
                :helper-text="
                  form.ldap_domain
                    ? $t('settings.admin_groups_helper')
                    : $t('settings.admin_groups_no_domain_helper')
                "
                :invalid-message="error.admin_groups"
                :disabled="loading.configureModule"
                :filterable="true"
                :auto-filter="true"
                :auto-highlight="true"
                :accept-user-input="true"
                :show-selected-items="true"
                :show-item-type="true"
                :show-item-description="true"
                :margin-bottom-on-open="true"
                :max-display-options="500"
                :selected-label="$t('settings.selected_label')"
                :user-input-label="$t('settings.custom_group_type')"
                :clear-selection-aria-label="$t('settings.clear_selection')"
                :unselect-aria-label="$t('settings.unselect_group')"
                selected-items-color="blue"
              />

              <!-- Smart 1-click suggestions for detected administrative groups -->
              <div
                v-if="unselectedSuggestedGroups.length > 0"
                class="suggestions-bar"
              >
                <span class="suggestions-label">
                  {{ $t("settings.suggested_admin_groups") }}
                </span>
                <div class="suggestions-chips">
                  <button
                    v-for="cand in unselectedSuggestedGroups"
                    :key="cand.group"
                    type="button"
                    class="suggestion-chip"
                    :disabled="loading.configureModule"
                    @click="addSuggestedGroup(cand.group)"
                  >
                    <Add16 class="suggestion-chip-icon" />
                    <span>{{ cand.group }}</span>
                    <span class="suggestion-chip-count">
                      ({{ cand.user_count }})
                    </span>
                  </button>
                </div>
              </div>
            </div>

            <!-- Bootstrap Admin Toggle -->
            <NsToggle
              :label="$t('settings.bootstrap_admin_enabled')"
              value="bootstrap_admin_enabled"
              v-model="form.bootstrap_admin_enabled"
              :disabled="loading.configureModule"
              class="mg-bottom-md"
            >
              <template slot="text-left">{{ $t("common.disabled") }}</template>
              <template slot="text-right">{{ $t("common.enabled") }}</template>
            </NsToggle>

            <!-- Bootstrap Admin Credentials -->
            <template v-if="form.bootstrap_admin_enabled">
              <NsTextInput
                v-model.trim="form.bootstrap_admin_username"
                :label="$t('settings.bootstrap_admin_username')"
                :placeholder="$t('settings.bootstrap_admin_username_placeholder')"
                :invalid-message="error.bootstrap_admin_username"
                :disabled="loading.configureModule"
                class="mg-bottom-md"
              />

              <NsTextInput
                v-model="form.bootstrap_admin_password"
                type="password"
                :label="$t('settings.bootstrap_admin_password')"
                :placeholder="$t('settings.bootstrap_admin_password_placeholder')"
                :helper-text="
                  passwordAlreadyConfigured
                    ? $t('settings.bootstrap_admin_password_keep_helper')
                    : $t('settings.bootstrap_admin_password_new_helper')
                "
                :invalid-message="error.bootstrap_admin_password"
                :disabled="loading.configureModule"
                class="mg-bottom-lg"
              />
            </template>

            <NsButton
              kind="primary"
              :icon="Save20"
              :loading="loading.configureModule"
              :disabled="loading.configureModule"
              type="submit"
            >
              {{ $t("settings.save") }}
            </NsButton>
          </cv-form>
        </cv-tile>
      </cv-column>
    </cv-row>
  </cv-grid>
</template>

<script>
import Add16 from "@carbon/icons-vue/es/add/16";
import Renew16 from "@carbon/icons-vue/es/renew/16";
import Save20 from "@carbon/icons-vue/es/save/20";
import {
  PageTitleService,
  QueryParamService,
  TaskService,
  UtilService,
} from "@nethserver/ns8-ui-lib";
import { mapState } from "vuex";
import to from "../utils/to";

function parseCsvGroups(raw) {
  if (!raw) {
    return [];
  }
  const seen = new Set();
  const result = [];
  for (const part of String(raw).split(",")) {
    const clean = part.trim();
    if (!clean) {
      continue;
    }
    const low = clean.toLowerCase();
    if (!seen.has(low)) {
      seen.add(low);
      result.push(clean);
    }
  }
  return result;
}

export default {
  name: "Settings",
  components: {
    Add16,
  },
  mixins: [TaskService, UtilService, QueryParamService, PageTitleService],
  pageTitle() {
    return this.$t("settings.title") + " - Advanced Policy Manager";
  },
  data() {
    return {
      Save20,
      Renew16,
      saveSucceeded: false,
      passwordAlreadyConfigured: false,
      userDomains: [],
      discoveredGroups: [],
      selectedAdminGroups: ["Domain Admins", "admins"],
      discoveryWarning: "",
      form: {
        host: "",
        lets_encrypt: false,
        http2https: true,
        ldap_domain: "",
        admin_groups: "Domain Admins,admins",
        bootstrap_admin_enabled: true,
        bootstrap_admin_username: "admin",
        bootstrap_admin_password: "",
      },
      loading: {
        getConfiguration: false,
        configureModule: false,
        listDomainGroups: false,
      },
      error: {
        host: "",
        admin_groups: "",
        bootstrap_admin_username: "",
        bootstrap_admin_password: "",
        configureModule: "",
      },
    };
  },
  computed: {
    ...mapState(["instanceName", "core"]),
    normalizedUserDomains() {
      if (!Array.isArray(this.userDomains)) {
        return [];
      }
      return this.userDomains
        .map((entry) => {
          if (typeof entry === "string") {
            return { value: entry, label: entry };
          }
          if (entry && typeof entry === "object") {
            const name = entry.name || entry.domain || "";
            let schemaLabel = "";
            if (entry.schema === "ad") {
              schemaLabel = ` (${this.$t("settings.schema_ad")})`;
            } else if (entry.schema === "rfc2307") {
              schemaLabel = ` (${this.$t("settings.schema_rfc2307")})`;
            } else if (entry.schema) {
              schemaLabel = ` (${entry.schema})`;
            }
            return { value: name, label: `${name}${schemaLabel}` };
          }
          return null;
        })
        .filter((item) => item && item.value);
    },
    adminGroupOptions() {
      const options = [];
      const seenValues = new Set();

      for (const grp of this.discoveredGroups) {
        if (!grp || !grp.group) {
          continue;
        }
        const name = String(grp.group).trim();
        if (!name || seenValues.has(name)) {
          continue;
        }
        seenValues.add(name);
        const countType = this.$t("settings.group_members_count", {
          count: Number(grp.user_count || 0),
        });
        const desc = grp.description ? `— ${grp.description}` : "";
        options.push({
          name,
          label: name,
          value: name,
          type: countType,
          description: desc,
        });
      }

      for (const selected of this.selectedAdminGroups) {
        const clean = String(selected || "").trim();
        if (!clean || seenValues.has(clean)) {
          continue;
        }
        seenValues.add(clean);
        options.push({
          name: clean,
          label: clean,
          value: clean,
          type: this.$t("settings.custom_group_type"),
          description: "",
        });
      }

      return options;
    },
    unselectedSuggestedGroups() {
      const selectedLower = new Set(
        this.selectedAdminGroups.map((g) => String(g).trim().toLowerCase())
      );
      return this.discoveredGroups
        .filter(
          (g) =>
            g &&
            g.group &&
            g.is_admin_candidate &&
            !selectedLower.has(String(g.group).trim().toLowerCase())
        )
        .slice(0, 8);
    },
  },
  watch: {
    instanceName: {
      immediate: true,
      handler(val) {
        if (val && this.core && this.core.$root) {
          this.getConfiguration();
        }
      },
    },
    selectedAdminGroups: {
      deep: true,
      handler(vals) {
        const cleaned = Array.isArray(vals)
          ? vals.map((v) => String(v || "").trim()).filter(Boolean)
          : [];
        this.form.admin_groups = cleaned.join(",");
      },
    },
  },
  methods: {
    clearErrors() {
      this.error = {
        host: "",
        admin_groups: "",
        bootstrap_admin_username: "",
        bootstrap_admin_password: "",
        configureModule: "",
      };
    },
    addSuggestedGroup(groupName) {
      const clean = String(groupName || "").trim();
      if (!clean) {
        return;
      }
      const exists = this.selectedAdminGroups.some(
        (g) => String(g).trim().toLowerCase() === clean.toLowerCase()
      );
      if (!exists) {
        this.selectedAdminGroups = [...this.selectedAdminGroups, clean];
      }
    },
    onDomainChanged() {
      this.discoveryWarning = "";
      if (this.form.ldap_domain) {
        this.discoverDomainGroups(this.form.ldap_domain);
      } else {
        this.discoveredGroups = [];
      }
    },
    async discoverDomainGroups(domainName) {
      const cleanDomain = String(domainName || "").trim();
      if (!cleanDomain) {
        this.discoveredGroups = [];
        return;
      }

      this.loading.listDomainGroups = true;
      this.discoveryWarning = "";
      const taskAction = "list-domain-groups";
      const eventId = this.getUuid();

      this.core.$root.$once(
        `${taskAction}-aborted-${eventId}`,
        this.listDomainGroupsAborted
      );
      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        this.listDomainGroupsCompleted
      );

      const [err] = await to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: { domain: cleanDomain },
          extra: {
            title: this.$t("action." + taskAction),
            isNotificationHidden: true,
            eventId,
          },
        })
      );

      if (err) {
        this.loading.listDomainGroups = false;
        this.discoveryWarning = this.$t("task.cannot_create_task", {
          action: taskAction,
        });
      }
    },
    listDomainGroupsAborted(taskResult, taskContext) {
      console.error(`${taskContext.action} aborted`, taskResult);
      this.loading.listDomainGroups = false;
      this.discoveryWarning = this.$t("settings.discovery_warning_title");
    },
    listDomainGroupsCompleted(taskContext, taskResult) {
      this.loading.listDomainGroups = false;
      if (taskResult && taskResult.output) {
        const out = taskResult.output;
        this.discoveredGroups = Array.isArray(out.groups) ? out.groups : [];
        this.discoveryWarning = out.error ? String(out.error) : "";
      }
    },
    validateForm() {
      this.clearErrors();
      let isValid = true;

      if (!this.form.host) {
        this.error.host = this.$t("settings.field_required");
        isValid = false;
      } else if (
        !/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/.test(
          this.form.host
        )
      ) {
        this.error.host = this.$t("settings.invalid_hostname");
        isValid = false;
      }

      if (
        !this.form.bootstrap_admin_enabled &&
        this.selectedAdminGroups.length === 0
      ) {
        this.error.admin_groups = this.$t("settings.at_least_one_admin_source");
        isValid = false;
      }

      if (
        this.form.bootstrap_admin_enabled &&
        !this.form.bootstrap_admin_username
      ) {
        this.error.bootstrap_admin_username = this.$t("settings.field_required");
        isValid = false;
      }

      return isValid;
    },
    async getConfiguration() {
      this.loading.getConfiguration = true;
      const taskAction = "get-configuration";
      const eventId = this.getUuid();

      this.core.$root.$once(
        `${taskAction}-aborted-${eventId}`,
        this.getConfigurationAborted
      );
      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        this.getConfigurationCompleted
      );

      const [err] = await to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          extra: {
            title: this.$t("action." + taskAction),
            isNotificationHidden: true,
            eventId,
          },
        })
      );

      if (err) {
        this.loading.getConfiguration = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task", { action: taskAction })
        );
      }
    },
    getConfigurationAborted(taskResult, taskContext) {
      console.error(`${taskContext.action} aborted`, taskResult);
      this.loading.getConfiguration = false;
    },
    getConfigurationCompleted(taskContext, taskResult) {
      if (taskResult && taskResult.output) {
        const cfg = taskResult.output;
        this.form.host = cfg.host || "";
        this.form.lets_encrypt = Boolean(cfg.lets_encrypt);
        this.form.http2https =
          cfg.http2https !== undefined ? Boolean(cfg.http2https) : true;
        this.userDomains = Array.isArray(cfg.user_domains)
          ? cfg.user_domains
          : [];

        let resolvedDomain = cfg.ldap_domain || "";
        if (!resolvedDomain && !cfg.host && this.normalizedUserDomains.length === 1) {
          resolvedDomain = this.normalizedUserDomains[0].value;
        }
        this.form.ldap_domain = resolvedDomain;

        const parsedGroups = parseCsvGroups(
          cfg.admin_groups !== undefined ? cfg.admin_groups : "Domain Admins,admins"
        );
        this.selectedAdminGroups = parsedGroups;
        this.form.admin_groups = parsedGroups.join(",");

        this.discoveredGroups = Array.isArray(cfg.discovered_groups)
          ? cfg.discovered_groups
          : [];

        this.form.bootstrap_admin_enabled =
          cfg.bootstrap_admin_enabled !== undefined
            ? Boolean(cfg.bootstrap_admin_enabled)
            : true;
        this.form.bootstrap_admin_username =
          cfg.bootstrap_admin_username || "admin";
        this.form.bootstrap_admin_password = "";
        this.passwordAlreadyConfigured = Boolean(
          cfg.bootstrap_admin_password_configured
        );

        if (this.form.ldap_domain && this.discoveredGroups.length === 0) {
          this.discoverDomainGroups(this.form.ldap_domain);
        }
      }
      this.loading.getConfiguration = false;
    },
    async configureModule() {
      this.saveSucceeded = false;
      if (!this.validateForm()) {
        return;
      }

      this.loading.configureModule = true;
      const taskAction = "configure-module";
      const eventId = this.getUuid();

      this.core.$root.$once(
        `${taskAction}-aborted-${eventId}`,
        this.configureModuleAborted
      );
      this.core.$root.$once(
        `${taskAction}-validation-failed-${eventId}`,
        this.configureModuleValidationFailed
      );
      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        this.configureModuleCompleted
      );

      const serializedGroups = this.selectedAdminGroups
        .map((g) => String(g || "").trim())
        .filter(Boolean)
        .join(",");

      const payload = {
        host: this.form.host,
        lets_encrypt: this.form.lets_encrypt,
        http2https: this.form.http2https,
        ldap_domain: this.form.ldap_domain,
        admin_groups: serializedGroups,
        bootstrap_admin_enabled: this.form.bootstrap_admin_enabled,
        bootstrap_admin_username: this.form.bootstrap_admin_username || "admin",
      };

      if (this.form.bootstrap_admin_password) {
        payload.bootstrap_admin_password = this.form.bootstrap_admin_password;
      }

      const [err] = await to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: payload,
          extra: {
            title: this.$t("settings.configure_instance", {
              instance: this.instanceName,
            }),
            description: this.$t("common.processing"),
            eventId,
          },
        })
      );

      if (err) {
        this.loading.configureModule = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task", { action: taskAction })
        );
      }
    },
    configureModuleAborted(taskResult, taskContext) {
      console.error(`${taskContext.action} aborted`, taskResult);
      this.loading.configureModule = false;
      this.error.configureModule = this.$t("error.cannot_configure_module");
    },
    configureModuleValidationFailed(validationErrors) {
      this.loading.configureModule = false;
      if (Array.isArray(validationErrors)) {
        for (const validationError of validationErrors) {
          const field = validationError.field || validationError.parameter;
          const errKey = `settings.${validationError.error}`;
          const message = this.$te(errKey)
            ? this.$t(errKey)
            : validationError.error;
          if (field && Object.prototype.hasOwnProperty.call(this.error, field)) {
            this.error[field] = message;
          } else {
            this.error.configureModule = message;
          }
        }
      }
    },
    configureModuleCompleted() {
      this.loading.configureModule = false;
      if (this.form.bootstrap_admin_password) {
        this.passwordAlreadyConfigured = true;
        this.form.bootstrap_admin_password = "";
      }
      this.saveSucceeded = true;
      this.getConfiguration();
    },
  },
};
</script>

<style scoped>
.group-discovery-box {
  border-left: 3px solid #0f62fe;
  padding-left: 0.875rem;
}

.discovery-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
  margin-bottom: 0.35rem;
  flex-wrap: wrap;
}

.discovery-status {
  font-size: 0.75rem;
  color: #525252;
  font-weight: 500;
}

.mg-bottom-sm {
  margin-bottom: 0.75rem;
}

.suggestions-bar {
  margin-top: 0.625rem;
}

.suggestions-label {
  display: block;
  font-size: 0.75rem;
  color: #525252;
  margin-bottom: 0.375rem;
}

.suggestions-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 0.375rem;
}

.suggestion-chip {
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
  border: 1px solid #d0e2ff;
  background-color: #edf5ff;
  color: #0043ce;
  border-radius: 9999px;
  padding: 0.15rem 0.6rem;
  font-size: 0.75rem;
  font-weight: 500;
  cursor: pointer;
  transition: background-color 0.12s ease, border-color 0.12s ease;
}

.suggestion-chip:hover:not(:disabled) {
  background-color: #d0e2ff;
  border-color: #0f62fe;
}

.suggestion-chip:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.suggestion-chip-icon {
  flex-shrink: 0;
}

.suggestion-chip-count {
  color: #0f62fe;
  font-size: 0.7rem;
}
</style>
