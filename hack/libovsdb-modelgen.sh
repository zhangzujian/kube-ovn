#! /usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

OVN_VERSION=${OVN_VERSION:-24.03}

go install github.com/ovn-org/libovsdb/cmd/modelgen

if [ ! -f ovn-nb.ovsschema ]; then
    curl -sSf -L -O --retry 5 https://raw.githubusercontent.com/ovn-org/ovn/branch-${OVN_VERSION}/ovn-nb.ovsschema
fi
if [ ! -f ovn-sb.ovsschema ]; then
    curl -sSf -L -O --retry 5 https://raw.githubusercontent.com/ovn-org/ovn/branch-${OVN_VERSION}/ovn-sb.ovsschema
fi

modelgen -p ovnnb -o pkg/ovsdb/ovnnb/ ovn-nb.ovsschema
modelgen -p ovnsb -o pkg/ovsdb/ovnsb/ ovn-sb.ovsschema
