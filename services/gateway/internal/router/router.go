package router

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/keyauth"
	"github.com/google/uuid"
	models "github.com/nekkkkitch/PostsModels"
)

type Client struct {
	conn   *websocket.Conn
	client uuid.UUID
}

type Router struct {
	App         *fiber.App
	config      *Config
	auth        IAuth
	subs        ISubs
	posts       IPosts
	notificator INotificator
	jwt         IJWT
	errs        map[error]struct{}
	roader      *Roader
}

type Roader struct {
	register   chan Client
	unregister chan Client
}

type Config struct {
	Port string `yaml:"port"`
}

type IAuth interface {
	Register(login, password string) error
	Login(login, password string) error
	RefreshTokens(access, refresh string) (string, string, error)
	SendEmail(user uuid.UUID, email string) error
	VerifyEmail(user uuid.UUID, code string) error
}

type ISubs interface {
	Subscribe(follower uuid.UUID, creator string) error
	UnSubscribe(follower uuid.UUID, creator string) error
	ShowSubscribers(user uuid.UUID) ([]byte, error)
	ShowFollowers(user uuid.UUID) ([]byte, error)
	BlackList(user uuid.UUID, toBan string) error
	UnBlackList(user uuid.UUID, toUnBan string) error
	ShowBlackList(user uuid.UUID) ([]byte, error)
}

type IPosts interface {
	AddPost(user uuid.UUID, title, description string) error
	ChangePost(user uuid.UUID, title, description string, post uuid.UUID) error
	DeletePost(user uuid.UUID, post uuid.UUID) error
	GetPosts(user uuid.UUID, creator string) ([]byte, error)
	GetFeed(user uuid.UUID) ([]byte, error)
}

type INotificator interface {
	NotificateUser(user uuid.UUID, c *websocket.Conn) error
	DeNotificateUser(user uuid.UUID) error
}

type IJWT interface {
	GetIDFromToken(token string) (uuid.UUID, error)
	ValidateToken(c *fiber.Ctx, key string) (bool, error)
	AuthFilter(c *fiber.Ctx) bool
	RefreshFilter(c *fiber.Ctx) bool
}

func New(cfg Config, auth IAuth, subs ISubs, posts IPosts, notificator INotificator, jwt IJWT) (*Router, error) {
	app := fiber.New()
	router := Router{App: app, auth: auth, subs: subs, posts: posts, notificator: notificator, jwt: jwt}
	router.App.Use("/ws", func(c *fiber.Ctx) error {
		if websocket.IsWebSocketUpgrade(c) {
			err := c.Next()
			if err != nil {
				log.Println(err.Error())
				return err
			}
		}
		return nil
	})
	router.App.Use(cors.New(cors.Config{
		AllowHeaders: "X-Access-Token, X-Refresh-Token",
	}))
	router.App.Use(keyauth.New(keyauth.Config{
		Next:         router.jwt.AuthFilter,
		KeyLookup:    "header:X-Access-Token",
		Validator:    router.jwt.ValidateToken,
		ErrorHandler: router.ErrorHandler(),
	}))
	router.App.Use(keyauth.New(keyauth.Config{
		Next:         router.jwt.RefreshFilter,
		KeyLookup:    "header:X-Refresh-Token",
		Validator:    router.jwt.ValidateToken,
		ErrorHandler: router.ErrorHandler(),
	}))
	go router.hub()
	router.App.Get("/notificateme", router.NotificateMe())
	router.App.Post("/login", router.Login())
	router.App.Post("/register", router.Register())
	router.App.Get("/refresh", router.RefreshTokens())
	router.App.Post("/sendemail", router.SendEmail())
	router.App.Post("/verifyemail", router.VerifyEmail())
	router.App.Post("/post", router.AddPost())
	router.App.Get("/posts", router.GetUserPosts()) // переделать получение логина из тела на url
	router.App.Delete("/post", router.DeletePost())
	router.App.Get("/feed", router.GetFeed())
	router.App.Post("/subscribe", router.Subscribe())
	router.App.Delete("/unsubscribe", router.UnSubscribe())
	router.App.Get("/subscribers", router.GetSubscribers()) // то же, что и в /posts
	router.App.Post("/blacklist", router.BlackList())
	router.App.Delete("/unblacklist", router.UnBlackList())
	router.App.Get("/blacklist", router.ShowBlackList())
	return &router, nil
}

func (r *Router) Listen() error {
	return r.App.Listen(r.config.Port)
}

// AUTH
func (r *Router) Login() fiber.Handler {
	return func(c *fiber.Ctx) error {
		body := c.Request().Body()
		params := make(map[string]string, 2)
		err := json.Unmarshal(body, &params)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		err = r.auth.Login(params["login"], params["password"])
		if err != nil {
			if _, ok := r.errs[err]; ok {
				c.Status(http.StatusBadRequest)
				return err
			}
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		c.Status(200)
		return nil
	}
}

func (r *Router) Register() fiber.Handler {
	return func(c *fiber.Ctx) error {
		body := c.Request().Body()
		params := make(map[string]string, 2)
		err := json.Unmarshal(body, &params)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		err = r.auth.Register(params["login"], params["password"])
		if err != nil {
			if _, ok := r.errs[err]; ok {
				c.Status(http.StatusBadRequest)
				return err
			}
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		c.Status(200)
		return nil
	}
}

func (r *Router) RefreshTokens() fiber.Handler {
	return func(c *fiber.Ctx) error {
		heads := c.GetReqHeaders()
		access := heads["X-Access-Token"][0]
		refresh := heads["X-Refresh-Token"][0]
		newAccess, newRefresh, err := r.auth.RefreshTokens(access, refresh)
		if err != nil {
			if _, ok := r.errs[err]; ok {
				c.Status(http.StatusBadRequest)
				return err
			}
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		c.Response().Header.Add("X-Access-Token", newAccess)
		c.Response().Header.Add("X-Refresh-Token", newRefresh)
		c.Status(200)
		return nil
	}
}

func (r *Router) SendEmail() fiber.Handler {
	return func(c *fiber.Ctx) error {
		access := c.GetReqHeaders()["X-Access-Headers"][0]
		params := map[string]string{}
		err := json.Unmarshal(c.Request().Body(), &params)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		id, err := r.jwt.GetIDFromToken(access)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		err = r.auth.SendEmail(id, params["email"])
		if err != nil {
			if _, ok := r.errs[err]; ok {
				c.Status(http.StatusBadRequest)
				return err
			}
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		c.Status(200)
		return nil
	}
}

func (r *Router) VerifyEmail() fiber.Handler {
	return func(c *fiber.Ctx) error {
		access := c.GetReqHeaders()["X-Access-Headers"][0]
		id, err := r.jwt.GetIDFromToken(access)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		params := map[string]string{}
		err = json.Unmarshal(c.Request().Body(), &params)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		err = r.auth.VerifyEmail(id, params["email_code"])
		if err != nil {
			if _, ok := r.errs[err]; ok {
				c.Status(http.StatusBadRequest)
				return err
			}
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		c.Status(200)
		return nil
	}
}

// POSTS
func (r *Router) AddPost() fiber.Handler {
	return func(c *fiber.Ctx) error {
		access := c.GetReqHeaders()["X-Access-Headers"][0]
		id, err := r.jwt.GetIDFromToken(access)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		params := map[string]string{}
		err = json.Unmarshal(c.Request().Body(), &params)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		err = r.posts.AddPost(id, params["title"], params["description"])
		if err != nil {
			if _, ok := r.errs[err]; ok {
				c.Status(http.StatusBadRequest)
				return err
			}
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		c.Status(200)
		return nil
	}
}

func (r *Router) ChangePost() fiber.Handler {
	return func(c *fiber.Ctx) error {
		access := c.GetReqHeaders()["X-Access-Headers"][0]
		id, err := r.jwt.GetIDFromToken(access)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		post := models.Post{}
		err = json.Unmarshal(c.Request().Body(), &post)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		err = r.posts.ChangePost(id, post.Title, post.Description, post.ID)
		if err != nil {
			if _, ok := r.errs[err]; ok {
				c.Status(http.StatusBadRequest)
				return err
			}
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		c.Status(200)
		return nil
	}
}

func (r *Router) DeletePost() fiber.Handler {
	return func(c *fiber.Ctx) error {
		access := c.GetReqHeaders()["X-Access-Headers"][0]
		id, err := r.jwt.GetIDFromToken(access)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		post := models.Post{}
		err = json.Unmarshal(c.Request().Body(), &post)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		err = r.posts.DeletePost(id, post.ID)
		if err != nil {
			if _, ok := r.errs[err]; ok {
				c.Status(http.StatusBadRequest)
				return err
			}
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		c.Status(200)
		return nil
	}
}

func (r *Router) GetUserPosts() fiber.Handler {
	return func(c *fiber.Ctx) error {
		access := c.GetReqHeaders()["X-Access-Headers"][0]
		id, err := r.jwt.GetIDFromToken(access)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		params := map[string]string{}
		err = json.Unmarshal(c.Request().Body(), &params)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		data, err := r.posts.GetPosts(id, params["creator"])
		if err != nil {
			if _, ok := r.errs[err]; ok {
				c.Status(http.StatusBadRequest)
				return err
			}
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		c.Status(200)
		err = c.JSON(data)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		return nil
	}
}

func (r *Router) GetFeed() fiber.Handler {
	return func(c *fiber.Ctx) error {
		access := c.GetReqHeaders()["X-Access-Headers"][0]
		id, err := r.jwt.GetIDFromToken(access)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		params := map[string]int{}
		err = json.Unmarshal(c.Request().Body(), &params)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		data, err := r.posts.GetFeed(id)
		if err != nil {
			if _, ok := r.errs[err]; ok {
				c.Status(http.StatusBadRequest)
				return err
			}
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		c.Status(200)
		err = c.JSON(data)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		return nil
	}
}

// SUBS
func (r *Router) Subscribe() fiber.Handler {
	return func(c *fiber.Ctx) error {
		access := c.GetReqHeaders()["X-Access-Headers"][0]
		id, err := r.jwt.GetIDFromToken(access)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		params := map[string]string{}
		err = json.Unmarshal(c.Request().Body(), &params)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		err = r.subs.Subscribe(id, params["creator"])
		if err != nil {
			if _, ok := r.errs[err]; ok {
				c.Status(http.StatusBadRequest)
				return err
			}
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		c.Status(200)
		return nil
	}
}

func (r *Router) UnSubscribe() fiber.Handler {
	return func(c *fiber.Ctx) error {
		access := c.GetReqHeaders()["X-Access-Headers"][0]
		id, err := r.jwt.GetIDFromToken(access)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		params := map[string]string{}
		err = json.Unmarshal(c.Request().Body(), &params)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		err = r.subs.UnSubscribe(id, params["creator"])
		if err != nil {
			if _, ok := r.errs[err]; ok {
				c.Status(http.StatusBadRequest)
				return err
			}
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		c.Status(200)
		return nil
	}
}

func (r *Router) GetSubscribers() fiber.Handler {
	return func(c *fiber.Ctx) error {
		access := c.GetReqHeaders()["X-Access-Headers"][0]
		id, err := r.jwt.GetIDFromToken(access)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		params := map[string]string{}
		err = json.Unmarshal(c.Request().Body(), &params)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		data, err := r.subs.ShowSubscribers(id)
		if err != nil {
			if _, ok := r.errs[err]; ok {
				c.Status(http.StatusBadRequest)
				return err
			}
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		c.Status(200)
		err = c.JSON(data)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		return nil
	}
}

func (r *Router) BlackList() fiber.Handler {
	return func(c *fiber.Ctx) error {
		access := c.GetReqHeaders()["X-Access-Headers"][0]
		id, err := r.jwt.GetIDFromToken(access)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		params := map[string]string{}
		err = json.Unmarshal(c.Request().Body(), &params)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		err = r.subs.BlackList(id, params["creator"])
		if err != nil {
			if _, ok := r.errs[err]; ok {
				c.Status(http.StatusBadRequest)
				return err
			}
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		c.Status(200)
		return nil
	}
}

func (r *Router) UnBlackList() fiber.Handler {
	return func(c *fiber.Ctx) error {
		access := c.GetReqHeaders()["X-Access-Headers"][0]
		id, err := r.jwt.GetIDFromToken(access)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		params := map[string]string{}
		err = json.Unmarshal(c.Request().Body(), &params)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		err = r.subs.UnBlackList(id, params["creator"])
		if err != nil {
			if _, ok := r.errs[err]; ok {
				c.Status(http.StatusBadRequest)
				return err
			}
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		c.Status(200)
		return nil
	}
}

func (r *Router) ShowBlackList() fiber.Handler {
	return func(c *fiber.Ctx) error {
		access := c.GetReqHeaders()["X-Access-Headers"][0]
		id, err := r.jwt.GetIDFromToken(access)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		params := map[string]string{}
		err = json.Unmarshal(c.Request().Body(), &params)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		data, err := r.subs.ShowBlackList(id)
		if err != nil {
			if _, ok := r.errs[err]; ok {
				c.Status(http.StatusBadRequest)
				return err
			}
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		c.Status(200)
		err = c.JSON(data)
		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return nil
		}
		return nil
	}
}

func (r *Router) ErrorHandler() func(c *fiber.Ctx, err error) error {
	return func(c *fiber.Ctx, err error) error {
		log.Println("Bad access token: ", c.GetReqHeaders()["X-Access-Token"])
		log.Println("Bad refresh token: ", c.GetReqHeaders()["X-Refresh-Token"])
		log.Println("Wrong jwts: " + err.Error())
		return err
	}
}

func (r *Router) NotificateMe() fiber.Handler {
	return websocket.New(func(c *websocket.Conn) {
		defer c.Close()
		access := c.Headers("X-Access-Token")
		subscriber, err := r.jwt.GetIDFromToken(access)
		if err != nil {
			return
		}
		r.roader.register <- Client{client: subscriber, conn: c}
		defer func() {
			r.roader.unregister <- Client{client: subscriber, conn: c}
		}()
		for {
			_, _, err = c.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Println("Error when reading message:", err.Error())
				}
				return
			}
		}
	})
}

func (r *Router) hub() {
	for {
		select {
		case u := <-r.roader.register:
			r.notificator.NotificateUser(u.client, u.conn)
		case u := <-r.roader.unregister:
			u.conn.Close()
			r.notificator.DeNotificateUser(u.client)
		}
	}
}
