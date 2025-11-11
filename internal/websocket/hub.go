// package websocket
package websocket // Используем main для возможности запуска и проверки

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// upgrader обновляет HTTP-соединения до протокола WebSocket.
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024 * 1024,
	WriteBufferSize: 1024 * 1024,
	// Проверяем origin, в продакшене здесь должна быть проверка домена.
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// WebsocketManager — это сервис, который управляет одним активным WebSocket соединением.
type WebsocketManager struct {
	activeConn *websocket.Conn
	connMutex  sync.RWMutex
	broadcast  chan []byte
}

func NewWebsocketManager() *WebsocketManager {
	return &WebsocketManager{
		broadcast: make(chan []byte, 256),
	}
}

// ServeHTTP обрабатывает входящие запросы на подключение.
func (m *WebsocketManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	// Получаем эксклюзивную блокировку для смены соединения.
	m.connMutex.Lock()
	// Если уже было старое соединение, закрываем его.
	if m.activeConn != nil {
		log.Println("Closing previous WebSocket connection to establish a new one.")
		m.activeConn.Close()
	}
	// Устанавливаем новое активное соединение.
	m.activeConn = conn
	log.Println("New WebSocket client connected.")
	m.connMutex.Unlock()

	ch := make(chan struct{})
	// Мы передаем управление жизненным циклом соединения этим двум горутинам.
	go m.writePump(conn, ch)
	m.readPump(conn, ch) // Запускаем readPump в текущей горутине, чтобы ServeHTTP не завершился.
}

// Broadcast отправляет данные активному клиенту.
func (m *WebsocketManager) Broadcast(data interface{}) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Failed to marshal message: %v", err)
		return
	}
	m.connMutex.RLock()
	isConnected := m.activeConn != nil
	m.connMutex.RUnlock()
	if isConnected {
		select {
		case m.broadcast <- jsonData:
		default:
			log.Println("Broadcast channel is full, skipping message.")
		}
	} else {
		log.Println("No active client to broadcast to, skipping message.")
	}
}

// writePump забирает сообщения из канала broadcast и отправляет их клиенту.
func (m *WebsocketManager) writePump(conn *websocket.Conn, ch chan struct{}) {
	defer conn.Close()
	for {
		select {
		case <-ch:
			log.Println("writePump: received disconnect signal, stopping writePump.")
			return
		case message, ok := <-m.broadcast:
			log.Printf("writePump: received message: %s", message)
			if !ok {
				log.Println("Broadcast channel closed, stopping writePump.")
				conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.TextMessage, message); err != nil {
				// Не логируем ошибку, если она связана с закрытием соединения,
				// так как это ожидаемое поведение при смене клиента.
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("Unexpected writePump error: %v", err)
				}
				log.Printf("writePump: closing connection: %v", err)
				return
			}
		}
	}
}

// readPump считывает сообщения от клиента для обнаружения разрыва соединения.
func (m *WebsocketManager) readPump(conn *websocket.Conn, ch chan struct{}) {
	defer func() {
		m.connMutex.Lock()
		// Очищаем ссылку только если это все еще то же самое соединение.
		if m.activeConn == conn {
			m.activeConn = nil
			log.Println("WebSocket client disconnected.")
			ch <- struct{}{}
		}
		m.connMutex.Unlock()
		conn.Close()
	}()

	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("Unexpected readPump error: %v", err)
			}
			break
		}
	}
}
