module websocket-server

go 1.21

toolchain go1.23.6

require (
	github.com/go-chi/render v1.0.3
	github.com/go-redis/redismock/v9 v9.2.0
	github.com/golang-jwt/jwt/v5 v5.0.0
	github.com/google/uuid v1.6.0
	github.com/gorilla/websocket v1.5.3
	github.com/jackc/pgx v3.6.2+incompatible
	github.com/jackc/pgx/v5 v5.7.2
	github.com/redis/go-redis/v9 v9.7.0
	golang.org/x/crypto v0.31.0
)

require (
	github.com/ajg/form v1.5.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/cockroachdb/apd v1.1.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/gofrs/uuid v4.4.0+incompatible // indirect
	github.com/jackc/fake v0.0.0-20150926172116-812a484cc733 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/lib/pq v1.10.9 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/text v0.21.0 // indirect
)

replace github.com/gocql/gocql => github.com/scylladb/gocql v1.7.0
