package models

import (
	"go.mongodb.org/mongo-driver/v2/bson"
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
