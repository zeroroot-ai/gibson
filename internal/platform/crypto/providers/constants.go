package providers

// expectedKeySize is the AES-256 master KEK byte length all providers
// validate against. Previously declared in kubernetes.go (deleted by
// ADR-0023 / S10); relocated here so the remaining providers (file,
// vault, aws, azure, gcp) share the constant without re-declaring it.
const expectedKeySize = 32
