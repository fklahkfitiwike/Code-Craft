// main.go

package main

import (
    "github.com/gin-gonic/gin"
    "golang.org/x/crypto/bcrypt"
    "github.com/dgrijalva/jwt-go"
    "net/http"
    "time"
)

// User represents a user in the system
type User struct {
    Username string `json:"username"`
    Email    string `json:"email"`
    Password string `json:"-"`
}

var users = map[string]User{}
var jwtKey = []byte("supersecretkey")

// Claims represents the structure of the JWT token
type Claims struct {
    Username string `json:"username"`
    jwt.StandardClaims
}

// Validate input based on type
func validateInput(input, inputType string) bool {
    var regexPattern string
    switch inputType {
    case "username":
        regexPattern = `^[a-zA-Z0-9_]{3,20}$`
    case "email":
        regexPattern = `^[^\s@]+@[^\s@]+\.[^\s@]+$`
    case "password":
        regexPattern = `^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$`
    default:
        return false
    }
    regex := regexp.MustCompile(regexPattern)
    return regex.MatchString(input)
}

func signUp(c *gin.Context) {
    var newUser User
    if err := c.BindJSON(&newUser); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid input"})
        return
    }

    if !validateInput(newUser.Username, "username") || !validateInput(newUser.Email, "email") || !validateInput(newUser.Password, "password") {
        c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid input"})
        return
    }

    if _, exists := users[newUser.Username]; exists {
        c.JSON(http.StatusBadRequest, gin.H{"message": "User already exists"})
        return
    }

    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"message": "Error creating user"})
        return
    }
    newUser.Password = string(hashedPassword)
    users[newUser.Username] = newUser

    c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully"})
}

func login(c *gin.Context) {
    var loginUser User
    if err := c.BindJSON(&loginUser); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid input"})
        return
    }

    storedUser, exists := users[loginUser.Username]
    if !exists || bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(loginUser.Password)) != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid credentials"})
        return
    }

    expirationTime := time.Now().Add(1 * time.Hour)
    claims := &Claims{
        Username: loginUser.Username,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: expirationTime.Unix(),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(jwtKey)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"message": "Error generating token"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func protected(c *gin.Context) {
    tokenString := c.GetHeader("Authorization")
    claims := &Claims{}

    token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
        return jwtKey, nil
    })

    if err != nil || !token.Valid {
        c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Welcome " + claims.Username})
}

func main() {
    r := gin.Default()

    r.POST("/api/signup", signUp)
    r.POST("/api/login", login)
    r.GET("/api/protected", protected)

    r.Run(":8080")
}