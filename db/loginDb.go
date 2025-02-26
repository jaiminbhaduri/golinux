package db

import (
	"context"
	"time"

	"github.com/jaiminbhaduri/golinux/models"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// EnsureTTLIndex ensures that the "exptime" field is indexed for automatic deletion
func EnsureTTLIndex(db *mongo.Database) error {
	collection := db.Collection("logins")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create an index on the "exptime" field with TTL
	indexModel := mongo.IndexModel{
		Keys:    bson.M{"exptime": 1},                     // Create index on exptime field
		Options: options.Index().SetExpireAfterSeconds(0), // Expire documents when time is reached
	}

	_, err := collection.Indexes().CreateOne(ctx, indexModel)
	return err
}

// SaveLogin inserts a login entry into the "logins" collection
func SaveLogin(db *mongo.Database, login *models.LoginStruct) (*mongo.InsertOneResult, error) {
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
