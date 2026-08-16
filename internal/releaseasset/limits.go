// Package releaseasset defines the bounded transport contract for governed
// GitHub release assets.
package releaseasset

// MaxBytes keeps a base64-encoded asset plus its operation envelope below the
// API's 42 MiB request limit and the worker RPC's 48 MiB message limit. A
// 31 MiB asset encodes to 41⅓ MiB, leaving room for JSON metadata.
//
// GitHub permits individual release assets up to 2 GiB, but GitOversight
// intentionally uses a smaller bound because the approved operation packet
// carries exact bytes inline for deterministic SHA-256 reconciliation.
const MaxBytes = 31 << 20
