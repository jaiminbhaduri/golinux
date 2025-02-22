package models

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// Login structure to store active user sessions
type Login struct {
	ID      primitive.ObjectID `bson:"_id,omitempty"`
	User    string             `json:"user"` // Username for quick lookup
	Uid     int32              `json:"uid"`  // Linux User ID
	Uuid    string             `json:"uuid"`
	LoginAt time.Time          `json:"login_at"` // Timestamp for login event
	Exptime time.Time          `json:"exptime"`
}

// SaveLogin inserts a login entry into the "logins" collection
func SaveLogin(db *mongo.Database, login *Login) error {
	login.LoginAt = time.Now().UTC()
	login.Exptime = time.Now().UTC().Add(1 * time.Hour)

	collection := db.Collection("logins")
	_, err := collection.InsertOne(context.TODO(), login)
	return err
}

func DeleteLogins(db *mongo.Database, users *[]string) (*mongo.DeleteResult, error) {
	collection := db.Collection("logins")

	// Use $in operator to match any of the users in the slice
	filter := bson.M{"user": bson.M{"$in": users}}

	output, err := collection.DeleteMany(context.TODO(), filter)
	return output, err
}
