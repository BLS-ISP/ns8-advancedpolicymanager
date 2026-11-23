<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-toolbar">
        <h2>{{ $t("about.title") }}</h2>
      </cv-column>
    </cv-row>

    <cv-row>
      <cv-column>
        <cv-tile kind="standard" :light="true" class="form-max-width">
          <cv-skeleton-text v-if="loading" :paragraph="true" :line-count="5" />

          <div v-else>
            <h3 class="mg-bottom-md">{{ appInfo.name }}</h3>
            <p class="mg-bottom-lg">{{ localizedDescription }}</p>

            <div class="kv-list">
              <div v-if="appInfo.docs && appInfo.docs.documentation_url" class="kv-row">
                <span class="kv-label">{{ $t("about.website") }}</span>
                <span class="kv-value">
                  <cv-link
                    :href="appInfo.docs.documentation_url"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    <span class="launch-btn-content">
                      <span>{{ appInfo.docs.documentation_url }}</span>
                      <Launch20 />
                    </span>
                  </cv-link>
                </span>
              </div>

              <div v-if="appInfo.docs && appInfo.docs.bug_url" class="kv-row">
                <span class="kv-label">{{ $t("about.bug_tracker") }}</span>
                <span class="kv-value">
                  <cv-link
                    :href="appInfo.docs.bug_url"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    <span class="launch-btn-content">
                      <span>{{ appInfo.docs.bug_url }}</span>
                      <Launch20 />
                    </span>
                  </cv-link>
                </span>
              </div>

              <div v-if="appInfo.docs && appInfo.docs.code_url" class="kv-row">
                <span class="kv-label">{{ $t("about.source_code") }}</span>
                <span class="kv-value">
                  <cv-link
                    :href="appInfo.docs.code_url"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    <span class="launch-btn-content">
                      <span>{{ appInfo.docs.code_url }}</span>
                      <Launch20 />
                    </span>
                  </cv-link>
                </span>
              </div>

              <div
                v-if="appInfo.authors && appInfo.authors.length"
                class="kv-row"
              >
                <span class="kv-label">{{ $t("about.authors") }}</span>
                <span class="kv-value">
                  {{
                    appInfo.authors
                      .map((a) => (a.email ? `${a.name} <${a.email}>` : a.name))
                      .join(", ")
                  }}
                </span>
              </div>

              <div
                v-if="appInfo.categories && appInfo.categories.length"
                class="kv-row"
              >
                <span class="kv-label">{{ $t("about.categories") }}</span>
                <span class="kv-value">
                  {{ appInfo.categories.join(", ") }}
                </span>
              </div>
            </div>
          </div>
        </cv-tile>
      </cv-column>
    </cv-row>
  </cv-grid>
</template>

<script>
import Launch20 from "@carbon/icons-vue/es/launch/20";
import { PageTitleService, TaskService, UtilService } from "@nethserver/ns8-ui-lib";

export default {
  name: "About",
  components: {
    Launch20,
  },
  mixins: [TaskService, UtilService, PageTitleService],
  pageTitle() {
    return this.$t("about.title") + " - Advanced Policy Manager";
  },
  data() {
    return {
      loading: true,
      appInfo: {
        name: "Advanced Policy Manager",
        description: {
          en: "Centralized policy and configuration management for Windows, Linux, and macOS endpoints",
        },
        categories: [],
        authors: [],
        docs: {},
      },
    };
  },
  computed: {
    localizedDescription() {
      const desc = this.appInfo.description;
      if (!desc) {
        return "";
      }
      if (typeof desc === "string") {
        return desc;
      }
      const locale = (this.$i18n && this.$i18n.locale) || "en";
      return desc[locale] || desc.en || "";
    },
  },
  async created() {
    try {
      const response = await this.axios.get("metadata.json");
      if (response && response.data) {
        this.appInfo = response.data;
      }
    } catch (err) {
      console.warn("Could not load metadata.json", err);
    } finally {
      this.loading = false;
    }
  },
};
</script>
