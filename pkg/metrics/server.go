package metrics

import (
	"context"
	"fmt"
	"net/http"
	"net/http/pprof"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func Run(ctx context.Context, config *rest.Config, addr string, secureServing, withPprof bool) error {
	if config == nil {
		config = ctrl.GetConfigOrDie()
	}
	client, err := rest.HTTPClientFor(config)
	if err != nil {
		klog.Error(err)
		return fmt.Errorf("failed to create http client: %w", err)
	}

	options := server.Options{
		SecureServing: secureServing,
		BindAddress:   addr,
		ExtraHandlers: map[string]http.Handler{},
	}
	if secureServing {
		options.FilterProvider = filters.WithAuthenticationAndAuthorization
	} else {
		handler := promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{
			ErrorHandling: promhttp.HTTPErrorOnError,
		})
		options.ExtraHandlers["/metrics/"] = handler
	}
	if withPprof {
		options.ExtraHandlers["/debug/pprof/"] = http.HandlerFunc(pprof.Index)
		options.ExtraHandlers["/debug/pprof/cmdline"] = http.HandlerFunc(pprof.Cmdline)
		options.ExtraHandlers["/debug/pprof/profile"] = http.HandlerFunc(pprof.Profile)
		options.ExtraHandlers["/debug/pprof/symbol"] = http.HandlerFunc(pprof.Symbol)
		options.ExtraHandlers["/debug/pprof/trace"] = http.HandlerFunc(pprof.Trace)
	}
	svr, err := server.NewServer(options, config, client)
	if err != nil {
		klog.Error(err)
		return fmt.Errorf("failed to create metrics server: %w", err)
	}

	return svr.Start(ctx)
}
