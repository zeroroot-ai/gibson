package redisprefixviolation

// redisClient is a local stub that mimics the methods inspected by the
// forbidrediskeyprefix analyzer.  The analyzer is name-based and does not
// perform type-checking, so a local stub is sufficient for the test fixture.
type redisClient struct{}

func (r *redisClient) Set(key, val string)                  {}
func (r *redisClient) Get(key string)                       {}
func (r *redisClient) Del(keys ...string)                   {}
func (r *redisClient) HSet(key string, args ...interface{}) {}

func badStore(client *redisClient, tenantID string) {
	client.Set("tenant:"+tenantID+":missions", "val") // want `tenant key-prefix pattern "tenant:"`
	client.Get("tenant:" + tenantID)                  // want `tenant key-prefix pattern "tenant:"`
	client.HSet("gibson:tenant:"+tenantID, "f", "v")  // want `tenant key-prefix pattern "gibson:tenant:"`
}
