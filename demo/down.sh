#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"

step "delete minikube profile $PROFILE"
minikube delete -p "$PROFILE"

if [ "${1:-}" = "--purge" ]; then
    step "remove generated secrets"
    rm -rf "$SECRETS"
fi
