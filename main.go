package main

import (
	"strconv"
	"time"
	"github.com/dgrijalva/jwt-go/v4"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB

const SecretKey = "secret"

func main() {
   type User struct {
	   Id uint `json:"id"`
	   Name string `json:"name"`
	   Email string `json:"email" gorm:"unique"`
	   Password []byte `json:"-"`
   }

	connection, err := gorm.Open(mysql.Open("root:root@/golang-jwt"), &gorm.Config{})

	if err != nil {
		panic("could not connect to the database")
	}
	DB = connection

	app := fiber.New()

	app.Use(cors.New(cors.Config{
		AllowCredentials: true,
	}))

	app.Post("/api/register", func(c *fiber.Ctx) error {
		var data map[string]string

		if err := c.BodyParser(&data); err != nil {
			return err
		}

		password, _ := bcrypt.GenerateFromPassword([]byte(data["password"]), 14)
		user := User{
			Name: data["name"],
			Email: data["email"],
			Password: password,
		}

		DB.Create(&user)

		return c.JSON(user)
	})

	app.Post("/api/login", func(c *fiber.Ctx) error {
		var data map[string]string

		if err := c.BodyParser(&data); err != nil {
			return err
		}

		var user User

		if DB.Where("email = ?", data["email"]).First(&user); user.Id == 0 {
			c.Status(fiber.StatusNotFound)
			return c.JSON(fiber.Map{
				"message": "user not found",
			})
		}

		if err := bcrypt.CompareHashAndPassword(user.Password, []byte(data["password"])); err != nil {
			c.Status(fiber.StatusBadRequest)
			return c.JSON(fiber.Map{
				"message": "incorrect password",
			})
		}

		claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
			Issuer: strconv.Itoa(int(user.Id)),
			// ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
		})

		token, err := claims.SignedString([]byte(SecretKey))

		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return c.JSON(fiber.Map{
				"message": "could not login",
			})
		}

		cookie := fiber.Cookie {
			Name: "jwt",
			Value: token,
			// Expires: time.Now().Add(time.Hour * 24).Unix(),
			HTTPOnly: true,
		}

		c.Cookie(&cookie)

		return c.JSON(fiber.Map{
			"message": "success",
		})
	})

	app.Get("/api/user", func(c *fiber.Ctx) error {
		cookie := c.Cookies("jwt")

		token, err := jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(t *jwt.Token) (interface{}, error) {
			return []byte(SecretKey), nil
		})

		if err != nil {
			// c.Status(fiber.StatusUnauthorized)
			return c.JSON(fiber.Map{
				"message": "unauthenticated",
			})
		}

		claims := token.Claims.(*jwt.StandardClaims)

		var user User

		DB.Where("id = ?", claims.Issuer).First(&user)

		return c.JSON(user)
	})

	app.Get("/api/logout", func(c *fiber.Ctx) error {
		cookie := fiber.Cookie {
			Name: "jwt",
			Value: "",
			Expires: time.Now().Add(-time.Hour),
			HTTPOnly: true,
		}

		c.Cookie(&cookie)

		return c.JSON(fiber.Map{
			"message": "success",
		})
	})

	app.Post("/api/delete", func(c *fiber.Ctx) error {
		var data map[string]string

		if err := c.BodyParser(&data); err != nil {
			return err
		}

        var user User

		DB.Delete(&user, data["id"])
		return c.JSON(fiber.Map{
			"message": "success",
		})
	})


	connection.AutoMigrate(&User{})

	app.Listen(":8000")
}
