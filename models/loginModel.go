package models

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Login structure to store active user sessions
type LoginStruct struct {
	ID        bson.ObjectID `bson:"_id,omitempty"`
	User      string        `json:"user"` // Username for quick lookup
	Userid    string        `json:"userid"`
	Mac       string        `json:"mac"`
	Ip        string        `json:"ip"`
	UserAgent string        `json:"useragent"`
	LoginAt   time.Time     `json:"login_at"`               // Timestamp for login event
	Exptime   time.Time     `json:"exptime" bson:"exptime"` // Index will be created on this field
}
