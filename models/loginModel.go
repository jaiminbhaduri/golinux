package models

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// Login structure to store active user sessions
type LoginStruct struct {
	ID        bson.ObjectID `bson:"_id,omitempty"`
	User      string        `json:"user"` // Username for quick lookup
	Userid    string        `json:"userid"`
	Mac       string        `json:"mac"`
	Ip        string        `json:"ip"`
	UserAgent string        `json:"useragent"`
	LoginAt   time.Time     `json:"login_at"` // Timestamp for login event
	Exptime   time.Time     `json:"exptime"`
}

// SaveLogin inserts a login entry into the "logins" collection
func SaveLogin(db *mongo.Database, login *LoginStruct) (*mongo.InsertOneResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
	defer cancel()

	collection := db.Collection("logins")
	output, err := collection.InsertOne(ctx, login)
	return output, err
}

// Delete multiple records of users on users' deletion
func DeleteLogins(db *mongo.Database, users *[]string) (*mongo.DeleteResult, error) {
	collection := db.Collection("logins")
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
	defer cancel()

	// Use $in operator to match any of the users in the slice
	filter := bson.M{"user": bson.M{"$in": users}}

	output, err := collection.DeleteMany(ctx, filter)
	return output, err
}

// Delete records on a user logout
func LogoutDeletion(db *mongo.Database, logindoc bson.M) (*mongo.DeleteResult, error) {
	collection := db.Collection("logins")
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
	defer cancel()

	user, _ := logindoc["user"].(string)
	uuid, _ := logindoc["uuid"].(string)
	loginuid, _ := logindoc["loginuid"].(string)

	// Use $in operator to match any of the users in the slice
	filter := bson.M{"user": user, "userid": uuid, "loginuid": loginuid}

	output, err := collection.DeleteMany(ctx, filter)
	return output, err
}
