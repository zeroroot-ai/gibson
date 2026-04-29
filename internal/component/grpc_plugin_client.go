package component

// grpc_plugin_client.go: the pre-release GRPCPluginClient (backed by
// PluginService Initialize/Query/Shutdown/Health/ListMethods RPCs) has been
// deleted by the plugin-runtime spec (Spec 2, Phase 1-2).
//
// The PluginService proto (core/sdk/api/proto/gibson/plugin/v1/plugin.proto)
// and its generated bindings have been removed.
//
// TODO(plugin-runtime Phase 7): replace with the production daemon-side plugin
// dispatch client that uses ComponentService PollWork/SubmitResult and the new
// PluginInvokeService (invoke.proto) defined in Phase 6. The new client lives
// in plugin_dispatch.go and plugin_registry.go (per the spec design).
//
// The ComponentDiscovery.DiscoverPlugin interface method is retained but its
// implementation is stubbed below until Phase 7.
