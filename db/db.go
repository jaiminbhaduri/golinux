package db

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

var client *mongo.Client // Global client variable

// Initdb initializes the database connection and stores the client
func Initdb() {
	var uri string
	if uri = os.Getenv("MONGODB_URI"); uri == "" {
		log.Fatal("You must set your 'MONGODB_URI' environment variable.")
	}

	// Set MongoDB options
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	opts := options.Client().ApplyURI(uri).SetServerAPIOptions(serverAPI)

	// Create a new client and store it in the global variable
	var err error
	client, err = mongo.Connect(opts)
	if err != nil {
		panic(err)
	}

	// Send a ping to confirm a successful connection
	var result bson.M
	if err := client.Database("golinux").RunCommand(context.TODO(), bson.M{"ping": 1}).Decode(&result); err != nil {
		panic(err)
	}
	fmt.Println("Pinged your deployment. You successfully connected to db!")
}

// GetDB returns the database instance
func GetDB() (*mongo.Database, error) {
	if client == nil {
		return nil, errors.New("DB client is not initialized")
	}
	return client.Database("golinux"), nil
}

// CloseDB closes the database connection
func CloseDB() {
	if client != nil {
		_ = client.Disconnect(context.TODO())
		log.Println("Disconnected from db")
	}
}
