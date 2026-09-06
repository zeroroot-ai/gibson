package trustlocalhost

type Config struct {
	TrustLocalhost bool // want `TrustLocalhost was removed`
}

func use(c Config) bool { return c.TrustLocalhost } // want `TrustLocalhost was removed`
