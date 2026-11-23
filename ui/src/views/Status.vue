<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-toolbar">
        <h2>{{ $t("status.title") }}</h2>
        <NsButton
          v-if="config.app_url"
          kind="primary"
          @click="openPolicyWebApp"
        >
          <span class="launch-btn-content">
            <span>{{ $t("status.open_webapp") }}</span>
            <Launch20 />
          </span>
        </NsButton>
      </cv-column>
    </cv-row>

    <cv-row v-if="!loading.getConfiguration && !config.host" class="mg-bottom-md">
      <cv-column>
        <NsInlineNotification
          kind="warning"
          :title="$t('common.not_configured')"
          :description="$t('status.not_configured_yet')"
          :actionLabel="$t('status.go_to_settings')"
          @action="goToSettings"
          :showCloseButton="false"
        />
      </cv-column>
    </cv-row>

    <!-- Overview Cards -->
    <div class="card-grid">
      <NsInfoCard
        light
        :title="instanceLabel || instanceName || $t('status.app_instance')"
        :description="$t('status.app_instance')"
        :icon="Application32"
        :loading="loading.getConfiguration"
      >
        <template slot="content">
          <div class="kv-list">
            <div class="kv-row">
              <span class="kv-label">{{ $t("status.webapp_url") }}</span>
              <span class="kv-value">
                <cv-link
                  v-if="config.app_url"
                  :href="config.app_url"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  <span class="launch-btn-content">
                    <span>{{ config.app_url }}</span>
                    <Launch20 />
                  </span>
                </cv-link>
                <span v-else>{{ $t("common.not_configured") }}</span>
              </span>
            </div>
            <div class="kv-row">
              <span class="kv-label">{{ $t("settings.http2https") }}</span>
              <span class="kv-value">
                {{ config.http2https ? $t("common.enabled") : $t("common.disabled") }}
              </span>
            </div>
            <div class="kv-row">
              <span class="kv-label">{{ $t("settings.lets_encrypt") }}</span>
              <span class="kv-value">
                {{ config.lets_encrypt ? $t("common.enabled") : $t("common.disabled") }}
              </span>
            </div>
          </div>
        </template>
      </NsInfoCard>

      <NsInfoCard
        light
        :title="$t('status.directory_binding')"
        :description="$t('status.bound_user_domain')"
        :icon="Events32"
        :loading="loading.getConfiguration"
      >
        <template slot="content">
          <div class="kv-list">
            <div class="kv-row">
              <span class="kv-label">{{ $t("status.bound_user_domain") }}</span>
              <span class="kv-value">
                <cv-tag
                  v-if="config.ldap_domain"
                  kind="blue"
                  :label="config.ldap_domain"
                />
                <cv-tag
                  v-else
                  kind="gray"
                  :label="$t('status.unbound_domain')"
                />
              </span>
            </div>
            <div class="kv-row">
              <span class="kv-label">{{ $t("status.admin_groups") }}</span>
              <span class="kv-value">{{ config.admin_groups || "-" }}</span>
            </div>
            <div class="kv-row">
              <span class="kv-label">{{ $t("status.bootstrap_admin") }}</span>
              <span class="kv-value">
                <span v-if="config.bootstrap_admin_enabled">
                  {{ $t("common.enabled") }} ({{ config.bootstrap_admin_username }})
                </span>
                <span v-else>{{ $t("common.disabled") }}</span>
              </span>
            </div>
          </div>
        </template>
      </NsInfoCard>

      <NsInfoCard
        light
        :title="
          status.node
            ? $t('status.node', { node: status.node })
            : $t('status.installation_node')
        "
        :description="$t('status.installation_node')"
        :icon="EdgeNode32"
        :loading="loading.getStatus"
      />
    </div>

    <!-- Systemd Services -->
    <cv-row class="mg-bottom-md">
      <cv-column>
        <h4 class="mg-bottom-md">{{ $t("status.services") }}</h4>
        <div v-if="status.services && status.services.length" class="card-grid">
          <NsSystemdServiceCard
            v-for="service in status.services"
            :key="service.name"
            light
            :serviceName="service.name"
            :active="service.active"
            :failed="service.failed"
            :enabled="service.enabled"
            :activeLabel="$t('status.active')"
            :inactiveLabel="$t('status.inactive')"
            :enabledLabel="$t('status.enabled')"
            :disaledLabel="$t('status.disabled')"
            :failedLabel="$t('status.failed')"
            :icon="Cube32"
          />
        </div>
        <cv-tile v-else kind="standard" :light="true">
          {{ $t("status.no_services") }}
        </cv-tile>
      </cv-column>
    </cv-row>

    <!-- Container Images & Volumes -->
    <div class="card-grid">
      <cv-tile kind="standard" :light="true">
        <h4 class="mg-bottom-md">{{ $t("status.app_images") }}</h4>
        <cv-structured-list v-if="status.images && status.images.length">
          <template slot="headings">
            <cv-structured-list-heading>{{ $t("status.name") }}</cv-structured-list-heading>
            <cv-structured-list-heading>{{ $t("status.size") }}</cv-structured-list-heading>
            <cv-structured-list-heading>{{ $t("status.created") }}</cv-structured-list-heading>
          </template>
          <template slot="items">
            <cv-structured-list-item
              v-for="img in status.images"
              :key="img.name"
            >
              <cv-structured-list-data>{{ img.name }}</cv-structured-list-data>
              <cv-structured-list-data>{{ img.size | byteFormat }}</cv-structured-list-data>
              <cv-structured-list-data>{{ img.created || "-" }}</cv-structured-list-data>
            </cv-structured-list-item>
          </template>
        </cv-structured-list>
        <div v-else>{{ $t("status.no_images") }}</div>
      </cv-tile>

      <cv-tile kind="standard" :light="true">
        <h4 class="mg-bottom-md">{{ $t("status.app_volumes") }}</h4>
        <cv-structured-list v-if="status.volumes && status.volumes.length">
          <template slot="headings">
            <cv-structured-list-heading>{{ $t("status.name") }}</cv-structured-list-heading>
            <cv-structured-list-heading>{{ $t("status.mount") }}</cv-structured-list-heading>
          </template>
          <template slot="items">
            <cv-structured-list-item
              v-for="vol in status.volumes"
              :key="vol.name"
            >
              <cv-structured-list-data>{{ vol.name }}</cv-structured-list-data>
              <cv-structured-list-data>{{ vol.mount || "-" }}</cv-structured-list-data>
            </cv-structured-list-item>
          </template>
        </cv-structured-list>
        <div v-else>{{ $t("status.no_volumes") }}</div>
      </cv-tile>
    </div>
  </cv-grid>
</template>

<script>
import Launch20 from "@carbon/icons-vue/es/launch/20";
import Application32 from "@carbon/icons-vue/es/application/32";
import Events32 from "@carbon/icons-vue/es/events/32";
import EdgeNode32 from "@carbon/icons-vue/es/edge-node/32";
import Cube32 from "@carbon/icons-vue/es/cube/32";
import {
  PageTitleService,
  QueryParamService,
  TaskService,
  UtilService,
} from "@nethserver/ns8-ui-lib";
import { mapState } from "vuex";
import to from "../utils/to";

export default {
  name: "Status",
  components: {
    Launch20,
  },
  mixins: [TaskService, UtilService, QueryParamService, PageTitleService],
  pageTitle() {
    return this.$t("status.title") + " - Advanced Policy Manager";
  },
  data() {
    return {
      Application32,
      Events32,
      EdgeNode32,
      Cube32,
      config: {
        host: "",
        http2https: true,
        lets_encrypt: false,
        ldap_domain: "",
        admin_groups: "Domain Admins,admins",
        bootstrap_admin_enabled: true,
        bootstrap_admin_username: "admin",
        app_url: "",
      },
      status: {
        instance: "",
        node: null,
        services: [],
        images: [],
        volumes: [],
      },
      loading: {
        getStatus: false,
        getConfiguration: false,
      },
    };
  },
  computed: {
    ...mapState(["instanceName", "instanceLabel", "core"]),
  },
  watch: {
    instanceName: {
      immediate: true,
      handler(val) {
        if (val && this.core && this.core.$root) {
          this.getStatus();
          this.getConfiguration();
        }
      },
    },
  },
  methods: {
    openPolicyWebApp() {
      if (this.config.app_url) {
        window.open(this.config.app_url, "_blank", "noopener,noreferrer");
      }
    },
    goToSettings() {
      this.$router.push("/settings");
    },
    async getStatus() {
      this.loading.getStatus = true;
      const taskAction = "get-status";
      const eventId = this.getUuid();

      this.core.$root.$once(
        `${taskAction}-aborted-${eventId}`,
        this.getStatusAborted
      );
      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        this.getStatusCompleted
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
        this.loading.getStatus = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task", { action: taskAction })
        );
      }
    },
    getStatusAborted(taskResult, taskContext) {
      console.error(`${taskContext.action} aborted`, taskResult);
      this.loading.getStatus = false;
    },
    getStatusCompleted(taskContext, taskResult) {
      if (taskResult && taskResult.output) {
        this.status = taskResult.output;
      }
      this.loading.getStatus = false;
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
        this.config = {
          ...this.config,
          ...taskResult.output,
        };
      }
      this.loading.getConfiguration = false;
    },
  },
};
</script>
