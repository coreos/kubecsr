#!/bin/bash -e

if [[ $TRAVIS_PULL_REQUEST == "false" ]] && [[ $TRAVIS_BRANCH == "master" ]]; then
    docker login -u "$DOCKER_USERNAME" -p "$DOCKER_PASSWORD" quay.io;
    make push/kube-aws-approver;
fi
