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

            <!-- Admin LDAP/AD Groups -->
            <NsTextInput
              v-model.trim="form.admin_groups"
              :label="$t('settings.admin_groups')"
              :placeholder="$t('settings.admin_groups_placeholder')"
              :helper-text="$t('settings.admin_groups_helper')"
              :invalid-message="error.admin_groups"
              :disabled="loading.configureModule"
              class="mg-bottom-md"
            />

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
import Save20 from "@carbon/icons-vue/es/save/20";
import {
  PageTitleService,
  QueryParamService,
  TaskService,
  UtilService,
} from "@nethserver/ns8-ui-lib";
import { mapState } from "vuex";
import to from "../utils/to";

export default {
  name: "Settings",
  mixins: [TaskService, UtilService, QueryParamService, PageTitleService],
  pageTitle() {
    return this.$t("settings.title") + " - Advanced Policy Manager";
  },
  data() {
    return {
      Save20,
      saveSucceeded: false,
      passwordAlreadyConfigured: false,
      userDomains: [],
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
            const schema = entry.schema ? ` (${entry.schema})` : "";
            return { value: name, label: `${name}${schema}` };
          }
          return null;
        })
        .filter((item) => item && item.value);
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

      if (this.form.bootstrap_admin_enabled && !this.form.bootstrap_admin_username) {
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
        this.form.ldap_domain = cfg.ldap_domain || "";
        this.form.admin_groups = cfg.admin_groups || "Domain Admins,admins";
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
        this.userDomains = Array.isArray(cfg.user_domains)
          ? cfg.user_domains
          : [];
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

      const payload = {
        host: this.form.host,
        lets_encrypt: this.form.lets_encrypt,
        http2https: this.form.http2https,
        ldap_domain: this.form.ldap_domain,
        admin_groups: this.form.admin_groups || "Domain Admins,admins",
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
