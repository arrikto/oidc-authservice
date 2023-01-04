package sessions

import (
	"os"

	"github.com/arrikto/oidc-authservice/common"
	"github.com/boltdb/bolt"
	"github.com/emirpasic/gods/sets/hashset"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	"github.com/yosssi/boltstore/reaper"
	boltstore "github.com/yosssi/boltstore/store"
)

type boltDBSessionStore struct {
	sessions.Store
	// DB is the underlying BoltDB instance.
	DB *bolt.DB
	// Channels for BoltDB reaper
	// quitC sends the quit signal to the reaper goroutine.
	// doneC receives the signal that the reaper has quit.
	quitC chan<- struct{}
	doneC <-chan struct{}
}

type existingDBEntry struct {
	DB      *bolt.DB
	buckets *hashset.Set
}

var existingDBs = map[string]*existingDBEntry{}

// newBoltDBSessionStore returns a session store backed by BoltDB. The database
// is stored in the given path and keys are stored in the given bucket. If the
// path has been used before, it can reuses the same database if the
// allowDBReuse option is true.
// Returns the session store and a storeCloser interface, which should be called
// before shutting down in order to perform cleanup.
func newBoltDBSessionStore(path, bucket string, allowDBReuse bool) (*boltDBSessionStore, error) {

	// Get realpath if the file already exists
	_, err := os.Stat(path)
	if !os.IsNotExist(err) {
		path, err = common.RealPath(path)
		if err != nil {
			return nil, err
		}
	}

	// Retrieve existing DB or create new one
	var db *bolt.DB
	if existingDB, ok := existingDBs[path]; ok {
		if !allowDBReuse {
			return nil, errors.New("BoltDB instance is already used and allowDBReuse is false")
		}
		if existingDB.buckets.Contains(bucket) {
			return nil, errors.New("BoltDB instance already has a bucket " +
				"the same name used by another session store")
		}
		db = existingDB.DB
	} else {
		db, err = bolt.Open(path, 0600, nil)
		if err != nil {
			return nil, err
		}
		existingDBs[path] = &existingDBEntry{DB: db, buckets: hashset.New()}
	}

	// Create a session store backed by the given BoltDB instance
	store, err := boltstore.New(
		db,
		boltstore.Config{DBOptions: boltstore.Options{BucketName: []byte(bucket)}},
		[]byte(secureCookieKeyPair),
	)
	if err != nil {
		return nil, err
	}
	existingDBs[path].buckets.Add(bucket)
	// Invoke a reaper which checks and removes expired sessions periodically
	quitC, doneC := reaper.Run(db, reaper.Options{BucketName: []byte(bucket)})
	return &boltDBSessionStore{
		Store: store,
		DB:    db,
		doneC: doneC,
		quitC: quitC,
	}, nil
}

func (bsc *boltDBSessionStore) Close() error {
	reaper.Quit(bsc.quitC, bsc.doneC)
	return bsc.DB.Close()
}
