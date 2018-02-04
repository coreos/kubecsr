#!/usr/bin/env bash
set -euo pipefail

BUILD_IMAGE=${BUILD_IMAGE:-}
PUSH_IMAGE=${PUSH_IMAGE:-false}

if [ -z "${BUILD_IMAGE}" ]; then
    echo "BUILD_IMAGE env var must be set"
    exit 1
fi

REPO_ROOT=$(git rev-parse --show-toplevel)
VERSION=${VERSION:-$(${REPO_ROOT}/hack/git-version.sh)}
source "${REPO_ROOT}/hack/images/${BUILD_IMAGE}/build-image.sh"

image::build
if [[ ${PUSH_IMAGE} == "true" ]]; then
    docker push $(image::name)
fi