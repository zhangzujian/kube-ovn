package ovs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func (suite *OvnClientTestSuite) testOvnIcNbCommand() {
	t := suite.T()
	t.Parallel()

	ovnLegacyClient := suite.ovnLegacyClient
	cmd := []string{"--format=csv", "--data=bare", "--no-heading", "--columns=name", "list", "Transit_Switch"}
	output, err := ovnLegacyClient.ovnIcNbCommand(cmd...)
	// ovn-ic-nbctl not found
	// TODO: ic nb db use mock db like nb and sb
	require.Error(t, err)
	require.Empty(t, output)
}

func (suite *OvnClientTestSuite) testGetTsSubnet() {
	t := suite.T()
	t.Parallel()

	ovnLegacyClient := suite.ovnLegacyClient
	subnet, err := ovnLegacyClient.GetTsSubnet("ts1")
	// ovn-ic-nbctl not found
	// TODO: ic nb db use mock db like nb and sb
	require.Error(t, err)
	require.Empty(t, subnet)
}

func (suite *OvnClientTestSuite) testGetTs() {
	t := suite.T()
	t.Parallel()

	ovnLegacyClient := suite.ovnLegacyClient
	ts, err := ovnLegacyClient.GetTs()
	// ovn-ic-nbctl not found
	require.Error(t, err)
	require.Empty(t, ts)
}

func TestDistributedTransitSwitchExcludedFromLegacyGatewayDiscovery(t *testing.T) {
	fixture := t.TempDir()
	script := `#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  *ts-add*)
    printf '%s\n' "$@" > "$DIST_IC_FIXTURE/args"
    for arg in "$@"; do
      case "$arg" in external_ids:vendor=*) printf '%s' "${arg#external_ids:vendor=}" > "$DIST_IC_FIXTURE/vendor" ;; esac
    done
    ;;
  *find*)
    printf '%s\n' ts-gateway
    if [[ "$(cat "$DIST_IC_FIXTURE/vendor")" == '"kube-ovn"' ]]; then printf '%s\n' dist-ts-user; fi
    ;;
  *) exit 1 ;;
esac
`
	require.NoError(t, os.WriteFile(filepath.Join(fixture, OVNIcNbCtl), []byte(script), 0o700))
	t.Setenv("PATH", fixture+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("DIST_IC_FIXTURE", fixture)
	client := LegacyClient{OvnTimeout: 1, OvnICNbAddress: "tcp:127.0.0.1:16641"}
	require.NoError(t, client.EnsureTransitSwitch("dist-ts-user", "10.0.0.0/24"))
	switches, err := client.GetTs()
	require.NoError(t, err)
	require.Equal(t, []string{"ts-gateway"}, switches)
	raw, err := os.ReadFile(filepath.Join(fixture, "args"))
	require.NoError(t, err)
	args := string(raw)
	require.Contains(t, args, `external_ids:distributed-cidr="10.0.0.0/24"`)
	require.False(t, strings.Contains(args, "external_ids:subnet="))
	require.Contains(t, args, "remove\nTransit_Switch\ndist-ts-user\nexternal_ids\nsubnet")
}
