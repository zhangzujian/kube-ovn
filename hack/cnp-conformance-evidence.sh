#!/usr/bin/env bash
set -euo pipefail

# Capture startup failures before upstream conformance cleanup removes the Pods.
[[ "${GITHUB_ACTIONS:-}" == true ]]
[[ "$(kubectl config current-context)" == kind-kube-ovn ]]
suite_name=$1
shift
[[ "$suite_name" == cnp || "$suite_name" == anp ]]
evidence_dir="cnp-evidence/${suite_name}-startup"
mkdir -p "$evidence_dir"

collect_startup_evidence() {
  while true; do
    if kubectl --request-timeout=5s get pods -A -o json | jq '{items: [.items[] |
      select(.metadata.namespace | startswith("network-policy-conformance-")) |
      {metadata: {namespace: .metadata.namespace, name: .metadata.name, uid: .metadata.uid},
       nodeName: .spec.nodeName, status: .status}]}' > "$evidence_dir/pods.tmp" &&
       jq -e '.items | length > 0' "$evidence_dir/pods.tmp" >/dev/null; then
      mv "$evidence_dir/pods.tmp" "$evidence_dir/pods.json"
      while IFS=$'\t' read -r namespace pod container; do
        [[ -n "$namespace" ]] || continue
        log_file="$evidence_dir/${namespace}-${pod}-${container}.log"
        for log_mode in current previous; do
          log_args=()
          [[ "$log_mode" == current ]] || log_args+=(--previous)
          if kubectl --request-timeout=5s logs -n "$namespace" "$pod" -c "$container" \
            --timestamps --tail=80 "${log_args[@]}" > "${log_file}.${log_mode}.tmp" 2>/dev/null; then
            mv "${log_file}.${log_mode}.tmp" "${log_file}.${log_mode}"
          else
            rm -f "${log_file}.${log_mode}.tmp"
          fi
        done
      done < <(jq -r '.items[] | .metadata as $pod | .status.containerStatuses[]? |
        select(.restartCount > 0 or .state.terminated != null) |
        [$pod.namespace, $pod.name, .name] | @tsv' "$evidence_dir/pods.json")
    fi
    for node in $(kind get nodes --name kube-ovn); do
      {
        date -u +%FT%TZ
        docker exec "$node" ss -tanp '( sport >= :34345 and sport <= :34352 )'
      } >> "$evidence_dir/${node}-host-port-sockets.txt" 2>/dev/null || true
    done
    sleep 3
  done
}

collect_startup_evidence &
collector_pid=$!
trap 'kill "$collector_pid" 2>/dev/null || true; wait "$collector_pid" 2>/dev/null || true' EXIT
"$@"
