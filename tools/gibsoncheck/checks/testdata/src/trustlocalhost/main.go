// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package trustlocalhost

type Config struct {
	TrustLocalhost bool // want `TrustLocalhost was removed`
}

func use(c Config) bool { return c.TrustLocalhost } // want `TrustLocalhost was removed`
