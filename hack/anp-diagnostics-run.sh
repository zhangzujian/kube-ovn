#!/usr/bin/env bash
set -euo pipefail
[[ ${GITHUB_ACTIONS:-false} == true ]]
rounds=${ROUNDS:-1}
interval=${SNAPSHOT_INTERVAL:-2}
incidents=${MAX_INCIDENTS:-12}
[[ $rounds =~ ^[1-3]$ ]]
root=$(pwd)
mkdir -p anp-diagnostics
(cd test/anp && go test -c -o "$root/anp-diagnostics/anp.test" .)
result=0
for ((round=1; round<=rounds; round++)); do
  # Wait for the suite's own cleanup; never remove namespace finalizers.
  for ns in gryffindor slytherin hufflepuff ravenclaw forbidden-forrest; do
    kubectl wait --for=delete "namespace/network-policy-conformance-$ns" --timeout=180s
  done
  evidence="$root/anp-diagnostics/round-$round"
  mkdir -p "$evidence"
  set +e
  (cd test/anp && python "$root/hack/anp_diagnostics.py" --output "$evidence" \
    --trace --interval "$interval" --max-incidents "$incidents" -- \
    "$root/anp-diagnostics/anp.test" -test.v -test.timeout=30m -test.run='^TestAdminNetworkPolicyConformance$')
  code=$?
  set -e
  if ((code != 0 && result == 0)); then result=$code; fi
  if [[ -f anp-test-report.yaml ]]; then mv anp-test-report.yaml "$evidence/"; fi
  echo "Round $round exited $code"
done
exit "$result"
