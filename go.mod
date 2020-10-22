module github.com/arrikto/oidc-authservice

go 1.12

require (
	github.com/boltdb/bolt v1.3.1
	github.com/cenkalti/backoff/v4 v4.0.2
	github.com/coreos/go-oidc v2.1.0+incompatible
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.3
	github.com/gorilla/securecookie v1.1.1
	github.com/gorilla/sessions v1.2.0
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/pkg/errors v0.9.1
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	github.com/quasoft/memstore v0.0.0-20180925164028-84a050167438
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.4.0
	github.com/tevino/abool v0.0.0-20170917061928-9b9efcf221b5
	github.com/yosssi/boltstore v1.0.1-0.20150916121936-36632d491655
	golang.org/x/net v0.0.0-20200520182314-0ba52f642ac2 // indirect
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	gopkg.in/square/go-jose.v2 v2.3.1 // indirect
	k8s.io/api v0.18.2
	k8s.io/apimachinery v0.18.2
	k8s.io/apiserver v0.18.2
	k8s.io/client-go v0.18.2
	sigs.k8s.io/controller-runtime v0.6.0
)

// Needed for github.com/yosssi/boltstore
replace (
	code.google.com/p/gogoprotobuf => github.com/gogo/protobuf v1.0.0
	github.com/docker/docker => github.com/docker/engine v0.0.0-20191007211215-3e077fc8667a
)
