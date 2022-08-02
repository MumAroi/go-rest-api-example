package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Book struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Author string `json:"author"`
}

type Handler struct {
	db *gorm.DB
}

func (h *Handler) listBooksHandler(c *gin.Context) {
	var books []Book
	if result := h.db.Find(&books); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": result.Error.Error(),
		})
	}
	c.JSON(http.StatusOK, &books)
}

func (h *Handler) createBooksHandler(c *gin.Context) {
	var book Book
	if err := c.ShouldBindJSON(&book); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	if result := h.db.Create(&book); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": result.Error.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, book)
}

func (h *Handler) deleteBooksHandler(c *gin.Context) {
	id := c.Param("id")

	if result := h.db.Delete(&Book{}, id); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": result.Error.Error(),
		})
		return
	}

	c.Status(http.StatusNoContent)
}

func newHandler(db *gorm.DB) *Handler {
	return &Handler{db}
}

func loginHandler(c *gin.Context) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
	})

	ss, err := token.SignedString([]byte("mysignature"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": ss,
	})
}

func validateToken(token string) error {
	_, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte("mysignature"), nil
	})
	return err
}

func authorizationMiddleware(c *gin.Context) {
	s := c.Request.Header.Get("Authorization")

	token := strings.TrimPrefix(s, "Bearer ")

	if err := validateToken(token); err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
}

func main() {
	db, err := gorm.Open(sqlite.Open("develop.db"), &gorm.Config{})

	if err != nil {
		panic("filed to connect database")
	}

	db.AutoMigrate(&Book{})

	handler := newHandler(db)

	r := gin.New()

	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "hello word",
		})
	})

	r.POST("/login", loginHandler)

	protected := r.Group("/", authorizationMiddleware)

	protected.GET("/books", handler.listBooksHandler)

	protected.POST("/books", handler.createBooksHandler)

	protected.DELETE("/books/:id", handler.deleteBooksHandler)

	r.Run(":3000")
}
