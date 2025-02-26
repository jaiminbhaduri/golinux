package models

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

type ApiLogStruct struct {
	ID        bson.ObjectID     `bson:"_id,omitempty"`
	Timestamp time.Time         `bson:"timestamp"`
	Method    string            `bson:"method"`
	Path      string            `bson:"path"`
	IP        string            `bson:"ip"`
	UserAgent string            `bson:"user_agent"`
	Headers   map[string]string `bson:"headers"`
	Body      string            `bson:"body,omitempty"`
}

func SaveApi(db *mongo.Database, apiLog *ApiLogStruct) (*mongo.InsertOneResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	output, err := db.Collection("apis").InsertOne(ctx, apiLog)
	return output, err
}
