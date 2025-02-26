package models

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jaiminbhaduri/golinux/db"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// Define the User structure to match MongoDB schema
type User struct {
	ID         bson.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	User       string        `json:"user"`
	HomeDir    string        `json:"home,omitempty"`
	Shell      string        `json:"shell,omitempty"`
	Comment    string        `json:"comment,omitempty"`
	SystemUser bool          `json:"system_user"`
	Uid        int           `json:"uid"`
	Gid        int           `json:"gid"`
}

// SaveUser inserts a user into the "users" collection
func SaveUser(db *mongo.Database, user User) (*mongo.InsertOneResult, error) {
	collection := db.Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	output, err := collection.InsertOne(ctx, user)
	return output, err
}

// Deletes a user from the "users" collection
func DeleteUsers(db *mongo.Database, users *[]string) (*mongo.DeleteResult, error) {
	collection := db.Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Use $in operator to match any of the users in the slice
	filter := bson.M{"user": bson.M{"$in": users}}

	output, err := collection.DeleteMany(ctx, filter)

	// Delete records from logins table
	DeleteLogins(db, users)

	return output, err
}

func Rebuild_users_db() (*mongo.InsertManyResult, error) {
	// Open and read /etc/passwd efficiently
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil, err
	}

	var usersToInsert []interface{}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for _, line := range lines {
		slice := strings.Split(line, ":")

		// Ensure the line has at least 7 fields
		if len(slice) < 7 {
			continue
		}

		// Convert UID and GID from string to int
		uid, _ := strconv.Atoi(slice[2])
		gid, _ := strconv.Atoi(slice[3])

		systemuser := uid < 1000 // System users usually have UIDs below 1000

		user := User{
			User:       slice[0],
			HomeDir:    slice[5],
			Shell:      slice[6],
			Comment:    slice[4],
			SystemUser: systemuser,
			Uid:        uid,
			Gid:        gid,
		}

		// Append to batch insert list
		usersToInsert = append(usersToInsert, user)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get db client
	dbClient, _ := db.GetDB()

	// Delete the users collection
	dbClient.Collection("users").Drop(ctx)

	// Inserts sample documents into the collection
	result, err := dbClient.Collection("users").InsertMany(ctx, usersToInsert)

	return result, err
}
