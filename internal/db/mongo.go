package db

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Store struct {
	Client *mongo.Client
	DB     *mongo.Database
}

func Connect(uri, dbName string) *Store {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		log.Fatalf("mongo: connect failed: %v", err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		log.Fatalf("mongo: ping failed: %v", err)
	}
	log.Printf("mongo: connected to %s / db=%s", uri, dbName)

	s := &Store{Client: client, DB: client.Database(dbName)}
	s.ensureIndexes(ctx)
	return s
}

func (s *Store) ensureIndexes(ctx context.Context) {
	uniq := options.Index().SetUnique(true)

	s.DB.Collection("admin_users").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "email", Value: 1}}, Options: uniq,
	})
	s.DB.Collection("licenses").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "public_id", Value: 1}}, Options: uniq},
		{Keys: bson.D{{Key: "api_key_hash", Value: 1}}},
		{Keys: bson.D{{Key: "status", Value: 1}}},
	})
	s.DB.Collection("machines").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "license_id", Value: 1}, {Key: "fingerprint", Value: 1}},
		Options: uniq,
	})
	s.DB.Collection("quota_requests").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "license_id", Value: 1}, {Key: "status", Value: 1}},
	})
	s.DB.Collection("license_history").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "license_id", Value: 1}, {Key: "changed_at", Value: -1}},
	})
	s.DB.Collection("audit_log").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "at", Value: -1}},
	})
}

func (s *Store) C(name string) *mongo.Collection { return s.DB.Collection(name) }
