package component

// grpc_plugin_client.go: the pre-release GRPCPluginClient (backed by
// PluginService Initialize/Query/Shutdown/Health/ListMethods RPCs) has been
// deleted by the plugin-runtime spec (Spec 2, Phase 1-2).
//
// The PluginService proto (core/sdk/api/proto/gibson/plugin/v1/plugin.proto)
// and its generated bindings have been removed.
//
// The production daemon-side plugin dispatch client is implemented in
// plugin_dispatch.go (PluginInvokeService) and plugin_registry.go
// (postgresPluginRegistry). Both use ComponentService PollWork/SubmitResult
// and the PluginInvokeService (invoke.proto) defined in Phase 6.
//
// The ComponentDiscovery.DiscoverPlugin interface method is retained but its
// implementation is stubbed below — it is exercised via the PluginInvokeService
// path rather than a direct gRPC call to the plugin process.
