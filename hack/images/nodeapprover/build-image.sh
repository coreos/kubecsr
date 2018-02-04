#!/usr/bin/env bash
set -euo pipefail

IMAGE_REPO=${IMAGE_REPO:-quay.io/abhinavdahiya/nodeapprover}

function image::build() {
    local TEMP_DIR=$(mktemp -d -t nodeapprover.XXXX)

    cp $REPO_ROOT/_output/bin/nodeapprover ${TEMP_DIR}
    cp $REPO_ROOT/hack/images/nodeapprover/Dockerfile ${TEMP_DIR}

    docker build -t ${IMAGE_REPO}:${VERSION} -f ${TEMP_DIR}/Dockerfile ${TEMP_DIR}
    rm -rf ${TEMP_DIR}
}

function image::name() {
    echo "${IMAGE_REPO}:${VERSION}"
}