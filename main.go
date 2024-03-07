package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

const (
	db   = "mongodb://localhost:27017"
	host = "127.0.0.1"
	port = "8080"
)

var (
	client *mongo.Client
	jwtKey = []byte("my_secret_key")
)

type RefreshToken struct {
	UserID       string    `json:"user_id"`
	TokenHash    string    `json:"token_hash"`
	Expiry       time.Time `json:"expiry"`
	RefreshCount int       `json:"refresh_count"`
}

func mongoConnect() {
	clientOptions := options.Client().ApplyURI(db)
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(context.Background())
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	accessToken, err := createAccessToken(userID)
	if err != nil {
		http.Error(w, "Failed to create access token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := createRefreshToken(userID)
	if err != nil {
		http.Error(w, "Failed to create refresh token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"access_token":"%s", "refresh_token":"%s"}`, accessToken, refreshToken)
}

func refreshHandler(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.Header.Get("Authorization")
	if refreshToken == "" {
		http.Error(w, "Refresh token is required", http.StatusBadRequest)
		return
	}

	userID, err := validateRefreshToken(refreshToken)
	if err != nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	newAccessToken, err := createAccessToken(userID)
	if err != nil {
		http.Error(w, "Failed to create access token", http.StatusInternalServerError)
		return
	}

	newRefreshToken, err := createRefreshToken(userID)
	if err != nil {
		http.Error(w, "Failed to create refresh token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"access_token":"%s", "refresh_token":"%s"}`, newAccessToken, newRefreshToken)
}

func createAccessToken(userID string) (string, error) {
	claims := jwt.StandardClaims{
		ExpiresAt: time.Now().Add(15 * time.Minute).Unix(),
		Subject:   userID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString(jwtKey)
}

func createRefreshToken(userID string) (string, error) {
	token := uuid.New().String()
	tokenHash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	collection := client.Database("tokens").Collection("refresh_tokens")
	refreshToken := RefreshToken{
		UserID:       userID,
		TokenHash:    string(tokenHash),
		Expiry:       time.Now().Add(24 * time.Hour),
		RefreshCount: 0,
	}
	_, err = collection.InsertOne(context.Background(), refreshToken)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString([]byte(token)), nil
}

func validateRefreshToken(tokenString string) (string, error) {
	tokenBytes, err := base64.StdEncoding.DecodeString(tokenString)
	if err != nil {
		return "", err
	}
	token := string(tokenBytes)

	collection := client.Database("tokens").Collection("refresh_tokens")
	var refreshToken RefreshToken
	err = collection.FindOne(context.Background(), bson.M{"token_hash": token}).Decode(&refreshToken)
	if err != nil {
		return "", err
	}

	if time.Now().After(refreshToken.Expiry) {
		return "", fmt.Errorf("refresh token has expired")
	}

	_, err = collection.UpdateOne(context.Background(), bson.M{"token_hash": token}, bson.M{"$inc": bson.M{"refresh_count": 1}})
	if err != nil {
		return "", err
	}

	return refreshToken.UserID, nil
}

func main() {
	mongoConnect()

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/refresh", refreshHandler)

	fmt.Println("Server started at :8080")
	log.Fatal(http.ListenAndServe(net.JoinHostPort(host, port), nil))
}
