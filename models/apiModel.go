package models

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
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
