package websocket

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// временная заглушка
		return true
	},
}

type Hub struct {
	client     *Client
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
	mutex      sync.RWMutex
}

type Client struct {
	hub      *Hub
	conn     *websocket.Conn
	send     chan []byte
	isActive bool
}

func NewHub() *Hub {
	return &Hub{
		client:     &Client{isActive: false},
		broadcast:  make(chan []byte, 256),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

type Message struct {
	Type      string      `json:"type"`
	Data      interface{} `json:"data"`
	Timestamp int64       `json:"timestamp"`
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.client = client
			h.client.isActive = true
			log.Printf("WebSocket client connected")
		case <-h.unregister:
			h.client.isActive = false
			log.Printf("WebSocket client disconnected")

		case message := <-h.broadcast:
			select {
			case h.client.send <- message:
			default:
				close(h.client.send)
				h.client.isActive = false
			}
		}
	}
}

func (h *Hub) Broadcast(data interface{}) {
	msg := Message{
		Type:      "request",
		Data:      data,
		Timestamp: time.Now().Unix(),
	}

	jsonData, err := json.Marshal(msg)
	if err != nil {
		log.Printf("Failed to marshal message: %v", err)
		return
	}

	select {
	case h.broadcast <- jsonData:
	default:
		log.Println("Broadcast channel full, skipping message")
	}
}

func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	client := &Client{
		isActive: true,
		hub:      h,
		conn:     conn,
		send:     make(chan []byte, 256),
	}

	client.hub.register <- client

	go client.writePump()
	go client.readPump()
}

func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (c *Client) writePump() {
	defer c.conn.Close()

	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			c.conn.WriteMessage(websocket.TextMessage, message)
		}
	}
}
