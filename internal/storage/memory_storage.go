package storage

import (
	"net/http"
	"sync"
	"time"
)

type RequestData struct {
	ID        string      `json:"id"`
	URL       string      `json:"url"`
	Method    string      `json:"method"`
	Headers   http.Header `json:"headers"`
	Body      string      `json:"body"`
	Timestamp time.Time   `json:"timestamp"`
	Response  *ResponseData `json:"response,omitempty"`
}

type ResponseData struct {
	Status  int         `json:"status"`
	Headers http.Header `json:"headers"`
	Body    string      `json:"body"`
}

type MemoryStorage struct {
	requests map[string]*RequestData
	mu       sync.RWMutex
}

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		requests: make(map[string]*RequestData),
	}
}

func (s *MemoryStorage) StoreRequest(req *RequestData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests[req.ID] = req
}

func (s *MemoryStorage) GetRequest(id string) (*RequestData, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	req, ok := s.requests[id]
	return req, ok
}

func (s *MemoryStorage) GetAllRequests() []*RequestData {
	s.mu.RLock()
	defer s.mu.RUnlock()

	requests := make([]*RequestData, 0, len(s.requests))
	for _, req := range s.requests {
		requests = append(requests, req)
	}
	return requests
}

func (s *MemoryStorage) DeleteRequest(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.requests, id)
}
