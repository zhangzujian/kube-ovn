#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
INSTALL_SCRIPT="$SCRIPT_DIR/install.sh"
IMAGE_DOCKERFILE="$SCRIPT_DIR/Dockerfile"

grep -q '^DISABLE_LEGACY_CNI_EXECUTION=.*false' "$INSTALL_SCRIPT"
grep -q -- '--disable-legacy-cni-execution=true' "$INSTALL_SCRIPT"
grep -q 'runAsUser: ${CNI_SERVER_RUN_AS_USER}' "$INSTALL_SCRIPT"
! grep -Eq 'setcap .*CAP_SYS_ADMIN.*kube-ovn-daemon' "$IMAGE_DOCKERFILE"

# Evaluate the installer inputs and the generated capability selection without
# running the installer (which applies resources to the current Kubernetes
# context). ENABLE_IC is supplied so the prefix does not probe kubectl.
new_config=$(
  ENABLE_IC=false DISABLE_LEGACY_CNI_EXECUTION=true bash -c '
    source <(sed -n "1,145p" "$1")
    printf "%s\n%s\n%s" "$CNI_SERVER_RUN_AS_USER" "$CNI_SERVER_CAPABILITIES" "$CNI_SERVER_EXECUTION_ARGS"
  ' bash "$INSTALL_SCRIPT"
)
new_user=${new_config%%$'\n'*}
new_caps=${new_config#*$'\n'}
new_args=${new_caps#*$'\n'}
new_caps=${new_caps%%$'\n'*}
[[ "$new_user" == 65534 ]]
[[ "$new_caps" != *SYS_ADMIN* ]]
[[ "$new_caps" != *SYS_PTRACE* ]]
[[ "$new_args" == *--disable-legacy-cni-execution=true* ]]

legacy_config=$(
  ENABLE_IC=false DISABLE_LEGACY_CNI_EXECUTION=false bash -c '
    source <(sed -n "1,145p" "$1")
    printf "%s\n%s\n%s" "$CNI_SERVER_RUN_AS_USER" "$CNI_SERVER_CAPABILITIES" "$CNI_SERVER_EXECUTION_ARGS"
  ' bash "$INSTALL_SCRIPT"
)
legacy_user=${legacy_config%%$'\n'*}
legacy_caps=${legacy_config#*$'\n'}
legacy_args=${legacy_caps#*$'\n'}
legacy_caps=${legacy_caps%%$'\n'*}
[[ "$legacy_user" == 0 ]]
[[ "$legacy_caps" == *SYS_ADMIN* ]]
[[ "$legacy_caps" == *SYS_PTRACE* ]]
[[ -z "$legacy_args" ]]

echo 'install.sh CNI security mode checks passed'
