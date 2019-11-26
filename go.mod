module github.com/arrikto/oidc-authservice

go 1.12

require (
	code.google.com/p/gogoprotobuf v0.0.0-00010101000000-000000000000 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78 // indirect
	github.com/Microsoft/go-winio v0.4.14 // indirect
	github.com/boltdb/bolt v1.3.1
	github.com/containerd/containerd v1.3.0 // indirect
	github.com/coreos/go-oidc v2.1.0+incompatible
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v1.13.1
	github.com/docker/go-connections v0.4.0
	github.com/docker/go-units v0.4.0 // indirect
	github.com/gogo/protobuf v1.3.0 // indirect
	github.com/google/go-cmp v0.3.1 // indirect
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.3
	github.com/gorilla/sessions v1.2.0
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/opencontainers/go-digest v1.0.0-rc1 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/pkg/errors v0.8.1
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	github.com/quasoft/memstore v0.0.0-20180925164028-84a050167438
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.2.2
	github.com/tevino/abool v0.0.0-20170917061928-9b9efcf221b5
	github.com/yosssi/boltstore v1.0.1-0.20150916121936-36632d491655
	golang.org/x/crypto v0.0.0-20191002192127-34f69633bfdc // indirect
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	golang.org/x/time v0.0.0-20190921001708-c4c64cad1fd0 // indirect
	google.golang.org/grpc v1.24.0 // indirect
	gopkg.in/square/go-jose.v2 v2.3.1 // indirect
	gotest.tools v2.2.0+incompatible // indirect
)

// Needed for github.com/yosssi/boltstore
replace (
	code.google.com/p/gogoprotobuf => github.com/gogo/protobuf v1.0.0
	github.com/docker/docker => github.com/docker/engine v0.0.0-20191007211215-3e077fc8667a
)
