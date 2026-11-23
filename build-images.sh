#!/bin/bash

set -e

REPOBASE="${REPOBASE:-ghcr.io/nethserver}"
IMAGETAG="${IMAGETAG:-latest}"
APP_IMAGE="${REPOBASE}/advancedpolicymanager-app:${IMAGETAG}"
MODULE_IMAGE="${REPOBASE}/advancedpolicymanager:${IMAGETAG}"

if command -v podman >/dev/null 2>&1; then
    CONTAINER_ENGINE="${CONTAINER_ENGINE:-podman}"
else
    CONTAINER_ENGINE="${CONTAINER_ENGINE:-docker}"
fi

echo "Building application container image: ${APP_IMAGE}"
"${CONTAINER_ENGINE}" build -f Containerfile.app -t "${APP_IMAGE}" .

echo "Building NS8 rootless module image: ${MODULE_IMAGE}"
"${CONTAINER_ENGINE}" build \
    -f Containerfile \
    --build-arg "APP_IMAGE=${APP_IMAGE}" \
    -t "${MODULE_IMAGE}" \
    .

if [[ -n "${CI:-}" && -n "${GITHUB_OUTPUT:-}" ]]; then
    printf "images=%s,%s\n" "${APP_IMAGE}" "${MODULE_IMAGE}" >> "${GITHUB_OUTPUT}"
fi

if [[ "${PUSH_IMAGES:-0}" == "1" ]]; then
    "${CONTAINER_ENGINE}" push "${APP_IMAGE}"
    "${CONTAINER_ENGINE}" push "${MODULE_IMAGE}"
fi

echo "Successfully built:"
echo "  - ${APP_IMAGE}"
echo "  - ${MODULE_IMAGE}"
