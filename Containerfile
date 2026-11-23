# ==============================================================================
# Stage 1: Build NS8 Cluster-Admin Cockpit UI (Vue 2 + @nethserver/ns8-ui-lib)
# ==============================================================================
FROM docker.io/library/node:22-alpine AS ui-builder

WORKDIR /ui
COPY ui/package*.json ui/.npmrc* ./
RUN npm install --legacy-peer-deps
COPY ui/ ./
RUN npm run build

# ==============================================================================
# Stage 2: Prepare NS8 imageroot (strip CRLF, clean bytecode, set permissions)
# ==============================================================================
FROM docker.io/library/alpine:3.20 AS imageroot-prep

COPY imageroot /imageroot
RUN find /imageroot -name "__pycache__" -type d -exec rm -rf {} + && \
    find /imageroot -name "*.pyc" -delete && \
    find /imageroot -type f -exec sed -i 's/\r$//' {} + && \
    chmod +x /imageroot/actions/*/[0-9]* \
             /imageroot/events/*/[0-9]* \
             /imageroot/update-module.d/* \
             /imageroot/bin/*

# ==============================================================================
# Stage 3: Final Rootless NethServer 8 Module Image
# ==============================================================================
FROM scratch

ARG APP_IMAGE="ghcr.io/bls-isp/advancedpolicymanager-app:latest"

COPY --from=imageroot-prep /imageroot /imageroot
COPY --from=ui-builder /ui/dist /ui

LABEL org.opencontainers.image.source="https://github.com/BLS-ISP/ns8-advancedpolicymanager" \
      org.opencontainers.image.title="NS8 AdvancedPolicyManager" \
      org.opencontainers.image.description="Central policy, privilege, and workstation configuration manager for Windows, Linux, and macOS" \
      org.opencontainers.image.vendor="BLS-ISP" \
      org.opencontainers.image.licenses="GPL-3.0-or-later" \
      org.nethserver.name="advancedpolicymanager" \
      org.nethserver.description="Central policy, privilege, and workstation configuration manager for Windows, Linux, and macOS" \
      org.nethserver.authorizations="traefik@node:routeadm cluster:accountconsumer" \
      org.nethserver.tcp-ports-demand="1" \
      org.nethserver.rootfull="0" \
      org.nethserver.min-core="3.0.0-0" \
      org.nethserver.volumes="apm-data" \
      org.nethserver.images="${APP_IMAGE}"

ENTRYPOINT ["/"]
