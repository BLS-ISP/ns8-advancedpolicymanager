# NethServer 8 rootless module image (FROM scratch) for NS8-AdvancedPolicyManager
FROM docker.io/library/node:22-alpine AS ui-builder
WORKDIR /deps
COPY ui/package*.json ui/.npmrc* ./
RUN npm install
WORKDIR /src/ui
COPY ui/ ./
RUN rm -rf node_modules dist && cp -a /deps/node_modules ./node_modules && npm run build

FROM docker.io/library/alpine:3.20 AS imageroot-prep
COPY imageroot /imageroot
RUN find /imageroot -name "__pycache__" -type d -exec rm -rf {} + && \
    find /imageroot -name "*.pyc" -delete && \
    find /imageroot -type f -exec sed -i 's/\r$//' {} + && \
    chmod +x /imageroot/actions/*/[0-9]* \
             /imageroot/events/*/[0-9]* \
             /imageroot/update-module.d/* \
             /imageroot/bin/*

FROM scratch
ARG APP_IMAGE="ghcr.io/nethserver/advancedpolicymanager-app:latest"

COPY --from=imageroot-prep /imageroot /imageroot
COPY --from=ui-builder /src/ui/dist /ui

LABEL org.nethserver.authorizations="traefik@node:routeadm cluster:accountconsumer" \
      org.nethserver.tcp-ports-demand="1" \
      org.nethserver.rootfull="0" \
      org.nethserver.min-core="3.0.0-0" \
      org.nethserver.images="${APP_IMAGE}"
