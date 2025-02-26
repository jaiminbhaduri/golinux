package db

import (
	"context"
	"time"

	"github.com/jaiminbhaduri/golinux/models"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func SaveApi(db *mongo.Database, apiLog *models.ApiLogStruct) (*mongo.InsertOneResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	output, err := db.Collection("apis").InsertOne(ctx, apiLog)
	return output, err
}
