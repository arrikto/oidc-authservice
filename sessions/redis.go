package sessions

import (
	"context"

	"github.com/arrikto/oidc-authservice/common"
	"github.com/go-redis/redis/v8"
	"github.com/rbcervilla/redisstore/v8"
)


func newRedisSessionStore(addr, password, keyPrefix string, db int) (*redisstore.RedisStore, error) {
	log := common.StandardLogger()

	client := redis.NewClient(&redis.Options{
		Addr: addr,
		Password: password,
		DB: db,
	})

	store, err := redisstore.NewRedisStore(context.Background(), client)
	if err != nil {
		log.Fatal("failed to create redis store: ", err)
	}
	if keyPrefix != "" {
		store.KeyPrefix(keyPrefix)
	}
	return store, nil
}
