let features = import "features.toml" in
{
  optional_features = features.optional_features,
  capabilities = features.capabilities,
}