package main

import (
	"context"
	"log"

	"github.com/go-redis/redis/v8"
	"github.com/rbcervilla/redisstore/v8"
)


func newRedisSessionStore(addr string, keyPrefix string) (*redisstore.RedisStore, error) {

	client := redis.NewClient(&redis.Options{
		Addr: addr,
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
