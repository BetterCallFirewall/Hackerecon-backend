package storage

import (
	"net/http"
	"sync"
	"time"
)

type RequestData struct {
	ID        string
	URL       string
	Method    string
	Headers   http.Header
	Body      string
	Timestamp time.Time
	Analysis  *AnalysisResult
}

type ResponseData struct {
	Status  int
	Headers http.Header
	Body    string
}

type AnalysisResult struct {
	VulnerabilitiesFound bool                    `json:"vulnerabilities_found"`
	Findings            []VulnerabilityFinding   `json:"findings"`
	OverallRisk         string                  `json:"overall_risk"`
	PentesterActions    []string                `json:"pentester_actions"`
}

type VulnerabilityFinding struct {
	Type           string `json:"type"`
	Severity       string `json:"severity"`
	Location       string `json:"location"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
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
