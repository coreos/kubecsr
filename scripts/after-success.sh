#!/bin/bash -e

if [[ $TRAVIS_PULL_REQUEST == "false" ]] && [[ $TRAVIS_BRANCH == "master" ]]; then
    docker login -u "$DOCKER_USERNAME" -p "$DOCKER_PASSWORD" quay.io;
    make push/kube-aws-approver;
    make push/kube-etcd-signer-server;
    make push/kube-client-agent;
fi
