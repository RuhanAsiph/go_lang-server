package main

import (
	"log"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

const SecretKey = "secret"

func main() {
	//models
	type User struct {
		Id       uint   `json:"id"`
		Name     string `json:"name"`
		Uname    string `json:"uname"`
		Email    string `json:"email" gorm:"unique"`
		Password []byte `json:"-"`
	}

	//model for posts
	type Post struct {
		gorm.Model
		Id    uint   `json:"id"`
		Uname string `json:"uname"`
		Post  string `json:"post"`
	}

	dsn := "host=localhost user=postgres password=protos dbname=revagram port=5432 sslmode=disable TimeZone=Asia/Shanghai"
	connection, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	DB = connection
	if err != nil {
		panic("could not connect to the postgres db")
	}

	connection.AutoMigrate(&User{}, &Post{})

	app := fiber.New()
	app.Use(cors.New(cors.Config{
		AllowCredentials: true,
		AllowOrigins:     "http://localhost:3001",
	}))

	//register function
	app.Post("/api/register", func(c *fiber.Ctx) error {
		var data map[string]string

		if err := c.BodyParser(&data); err != nil {
			return err
		}

		//hash the psswd
		password, _ := bcrypt.GenerateFromPassword([]byte(data["password"]), 14)

		user := User{
			Name:     data["name"],
			Uname:    data["uname"],
			Email:    data["email"],
			Password: password,
		}

		connection.Create(&user)
		return c.JSON(user)

	})

	//login functionality
	app.Post("/api/login", func(c *fiber.Ctx) error {

		var data map[string]string

		if err := c.BodyParser(&data); err != nil {
			return err
		}

		var user User

		connection.Where("email = ?", data["email"]).First(&user)
		if user.Id == 0 {
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

		//jwt authentication

		claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
			Issuer:    strconv.Itoa(int(user.Id)),
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(), //oneday
		})

		token, err := claims.SignedString([]byte(SecretKey))

		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return c.JSON(fiber.Map{
				"message": "could not login",
			})
		}

		//store the token in cookie
		cookie := fiber.Cookie{
			Name:     "jwt",
			Value:    token,
			Expires:  time.Now().Add(time.Hour * 24),
			HTTPOnly: true,
		}
		c.Cookie(&cookie)
		return c.JSON(fiber.Map{
			"message": "success",
		})

	})

	//retrieve login user cookie
	app.Get("/api/user", func(c *fiber.Ctx) error {
		cookie := c.Cookies("jwt")
		token, err := jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(t *jwt.Token) (interface{}, error) {
			return []byte(SecretKey), nil
		})

		if err != nil {
			c.Status(fiber.StatusUnauthorized)
			return c.JSON(fiber.Map{
				"message": "unauthenticated",
			})
		}

		claims := token.Claims.(*jwt.StandardClaims)

		var user User

		connection.Where("id = ?", claims.Issuer).First(&user)

		return c.JSON(user)
	})

	//create logout route
	app.Post("/api/logout", func(c *fiber.Ctx) error {
		cookie := fiber.Cookie{
			Name:     "jwt",
			Value:    "",
			Expires:  time.Now().Add(-time.Hour),
			HTTPOnly: true,
		}

		c.Cookie(&cookie)

		return c.JSON(fiber.Map{
			"message": "success",
		})
	})

	//create post functionality

	app.Post("/api/:username/create-post", func(c *fiber.Ctx) error {
		var data map[string]string

		if err := c.BodyParser(&data); err != nil {
			return err
		}

		var uname = c.Params("username")

		post := Post{
			Uname: uname,
			Post:  data["post"],
		}

		connection.Create(&post)

		return c.JSON(post)
	})

	app.Get("/api/:username/get-posts", func(c *fiber.Ctx) error {
		username := c.Params("username")

		var post Post
		result := connection.Limit(10).Where("uname = ?", username).Find(&post)
		if err := result.Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"status": "fail", "message": "No note with that Id exists"})
			}
			return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"status": "fail", "message": err.Error()})
		}

		return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "success", "data": fiber.Map{"post": post}})
	})

	log.Fatal(app.Listen(":3000"))
}
