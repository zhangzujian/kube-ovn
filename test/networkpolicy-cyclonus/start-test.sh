#!/usr/bin/env bash

set -eo pipefail
set -xv

kubectl create ns netpol
kubectl create clusterrolebinding cyclonus --clusterrole=cluster-admin --serviceaccount=netpol:cyclonus
kubectl create sa cyclonus -n netpol
kubectl create -f cyclonus.yaml -n netpol
while ! kubectl wait pod --for=condition=Ready -l job-name=cyclonus -n netpol; do \
    sleep 3; \
done
kubectl logs -f -l job-name=cyclonus -n netpol
if kubectl logs -l job-name=cyclonus -n netpol | grep -w failed >/dev/null; then
    kubectl logs -l job-name=cyclonus -n netpol | grep -w failed >/dev/null
    exit 1
fi
