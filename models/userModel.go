package models

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// User struct represents a MongoDB document
type User struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	Name     string             `bson:"name"`
	Email    string             `bson:"email"`
	Password string             `bson:"password"`
}

// GetUserCollection returns the MongoDB collection for users
func GetUserCollection(db *mongo.Database) *mongo.Collection {
	return db.Collection("users")
}

// CreateUser inserts a new user into MongoDB
func CreateUser(db *mongo.Database, user User) (*mongo.InsertOneResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	collection := GetUserCollection(db)
	result, err := collection.InsertOne(ctx, user)
	if err != nil {
		log.Println("Error inserting user:", err)
		return nil, err
	}

	fmt.Println("User inserted:", result.InsertedID)
	return result, nil
}

// GetUserByEmail retrieves a user by email
func GetUserByEmail(db *mongo.Database, email string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	collection := GetUserCollection(db)

	var user User
	err := collection.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		log.Println("Error finding user:", err)
		return nil, err
	}

	return &user, nil
}
