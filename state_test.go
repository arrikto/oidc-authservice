// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package main

import (
	"github.com/quasoft/memstore"
	"log"
	"reflect"
	"testing"
)

func TestSaveLoad(t *testing.T) {

	store := memstore.NewMemStore([]byte(secureCookieKeyPair))
	state := newState("https://example.com/")

	// Check that save works with no errors
	id, err := state.save(store)
	if err != nil {
		t.Fatalf("Unexpected error while saving: %+v", err)
	}

	// Check that load works with no errors
	loadedState, err := load(store, id)
	if err != nil {
		t.Fatalf("Unexpected error while loading: %+v", err)
	}

	if !reflect.DeepEqual(loadedState, state) {
		log.Fatalf("Saved state and Loaded state and not equal. Got: '%v' ; Want: '%v'",
			loadedState, state)
	}
}
