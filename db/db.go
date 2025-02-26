package db

import (
	"context"
	"errors"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

var client *mongo.Client // Global client variable

// Initdb initializes the database connection and stores the client
func Initdb() error {
	var uri string
	if uri = os.Getenv("MONGODB_URI"); uri == "" {
		return errors.New("you must set your 'MONGODB_URI' environment variable")
	}

	// Set MongoDB options
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	opts := options.Client().ApplyURI(uri).SetServerAPIOptions(serverAPI)

	// Create a new client and store it in the global variable
	var err error
	client, err = mongo.Connect(opts)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Send a ping to confirm a successful connection
	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		return err
	}

	return nil
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
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		client.Disconnect(ctx)
		log.Println("Disconnected from db")
	}
}
