package redisprefixallowed

// redisClient is a local stub for the allowed-package fixture.
type redisClient struct{}

func (r *redisClient) Set(key, val string) {}
func (r *redisClient) Get(key string)      {}
func (r *redisClient) Del(keys ...string)  {}

// goodStore uses plain keys — no tenant prefix — because Conn.Redis is
// already scoped to the tenant's logical DB.
func goodStore(client *redisClient, missionID string) {
	client.Set("mission:"+missionID, "val")
	client.Get("credential:" + missionID)
	client.Del("stream:events")
}
