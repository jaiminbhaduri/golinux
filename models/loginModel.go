package models

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// Login structure to store active user sessions
type Login struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"`
	User      string             `json:"user"` // Username for quick lookup
	Uuid      string             `json:"uuid"`
	Mac       string             `json:"mac"`
	Ip        string             `json:"ip"`
	UserAgent string             `json:"useragent"`
	LoginUid  string             `json:"loginUid"`
	LoginAt   time.Time          `json:"login_at"` // Timestamp for login event
	Exptime   time.Time          `json:"exptime"`
}

// SaveLogin inserts a login entry into the "logins" collection
func SaveLogin(db *mongo.Database, login *Login) error {
	if login.LoginUid == "" {
		login.LoginUid = uuid.New().String()
	}

	collection := db.Collection("logins")
	_, err := collection.InsertOne(context.TODO(), login)
	return err
}

// Delete multiple records of users on users' deletion
func DeleteLogins(db *mongo.Database, users *[]string) (*mongo.DeleteResult, error) {
	collection := db.Collection("logins")

	// Use $in operator to match any of the users in the slice
	filter := bson.M{"user": bson.M{"$in": users}}

	output, err := collection.DeleteMany(context.TODO(), filter)
	return output, err
}

// Delete records on a user logout
func LogoutDeletion(db *mongo.Database, logindoc bson.M) (*mongo.DeleteResult, error) {
	collection := db.Collection("logins")

	user, _ := logindoc["user"].(string)
	uuid, _ := logindoc["uuid"].(string)
	loginuid, _ := logindoc["loginuid"].(string)

	// Use $in operator to match any of the users in the slice
	filter := bson.M{"user": user, "uuid": uuid, "loginuid": loginuid}

	output, err := collection.DeleteMany(context.TODO(), filter)
	return output, err
}
