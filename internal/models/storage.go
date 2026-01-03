package models

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// InMemoryGraph stores all analysis data in memory
// Provides thread-safe storage for all detective flow entities
type InMemoryGraph struct {
	mu sync.RWMutex

	// Core entities
	exchanges    map[string]*HTTPExchange
	observations map[string]*Observation
	leads        map[string]*Lead
	connections  []*Connection

	// Site view
	siteMap map[string]*SiteMapEntry

	// Context
	bigPicture *BigPicture

	// Counters for ID generation
	exchangeCount    int
	observationCount int
	leadCount        int
	connectionCount  int
}

// NewInMemoryGraph creates a new in-memory graph
func NewInMemoryGraph() *InMemoryGraph {
	return &InMemoryGraph{
		exchanges:    make(map[string]*HTTPExchange),
		observations: make(map[string]*Observation),
		leads:        make(map[string]*Lead),
		connections:  make([]*Connection, 0),
		siteMap:      make(map[string]*SiteMapEntry),
		bigPicture:   &BigPicture{},
	}
}

// StoreExchange stores an HTTP exchange and returns its ID
func (g *InMemoryGraph) StoreExchange(exchange *HTTPExchange) string {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Always generate a new ID internally to prevent race conditions
	g.exchangeCount++
	id := fmt.Sprintf("exch-%d", g.exchangeCount)

	// Store a copy to avoid external modifications
	stored := *exchange
	stored.ID = id
	g.exchanges[id] = &stored

	return id
}

// GetExchange retrieves an exchange by ID
func (g *InMemoryGraph) GetExchange(id string) (*HTTPExchange, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	exchange, ok := g.exchanges[id]
	if !ok {
		return nil, fmt.Errorf("exchange not found: %s", id)
	}
	return exchange, nil
}

// AddObservation adds an observation and returns its ID
func (g *InMemoryGraph) AddObservation(observation *Observation) string {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Always generate a new ID internally to prevent race conditions
	g.observationCount++
	id := fmt.Sprintf("obs-%d", g.observationCount)

	// Store a copy to avoid external modifications
	stored := *observation
	stored.ID = id
	if stored.CreatedAt.IsZero() {
		stored.CreatedAt = time.Now()
	}

	g.observations[id] = &stored
	return id
}

// GetObservation retrieves an observation by ID
func (g *InMemoryGraph) GetObservation(id string) (*Observation, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	observation, ok := g.observations[id]
	if !ok {
		return nil, fmt.Errorf("observation not found: %s", id)
	}
	return observation, nil
}

// GetRecentObservations returns the most recent n observations
func (g *InMemoryGraph) GetRecentObservations(n int) []*Observation {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if n <= 0 {
		return []*Observation{}
	}

	// Collect all observations
	observations := make([]*Observation, 0, len(g.observations))
	for _, obs := range g.observations {
		observations = append(observations, obs)
	}

	// Sort by CreatedAt descending (most recent first)
	sort.Slice(observations, func(i, j int) bool {
		return observations[i].CreatedAt.After(observations[j].CreatedAt)
	})

	// Return top n
	if n > len(observations) {
		n = len(observations)
	}
	return observations[:n]
}

// GetObservationsForLead returns all observations associated with a lead
func (g *InMemoryGraph) GetObservationsForLead(leadID string) []*Observation {
	g.mu.RLock()
	defer g.mu.RUnlock()

	lead, ok := g.leads[leadID]
	if !ok {
		return []*Observation{}
	}

	observation, ok := g.observations[lead.ObservationID]
	if !ok {
		return []*Observation{}
	}

	return []*Observation{observation}
}

// AddLead adds a lead and returns its ID
func (g *InMemoryGraph) AddLead(lead *Lead) string {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Always generate a new ID internally to prevent race conditions
	g.leadCount++
	id := fmt.Sprintf("lead-%d", g.leadCount)

	// Store a copy to avoid external modifications
	stored := *lead
	stored.ID = id
	if stored.CreatedAt.IsZero() {
		stored.CreatedAt = time.Now()
	}

	g.leads[id] = &stored
	return id
}

// GetLead retrieves a lead by ID
func (g *InMemoryGraph) GetLead(id string) (*Lead, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	lead, ok := g.leads[id]
	if !ok {
		return nil, fmt.Errorf("lead not found: %s", id)
	}
	return lead, nil
}

// AddConnection adds a connection between two entities
func (g *InMemoryGraph) AddConnection(id1, id2, reason string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.connectionCount++
	conn := &Connection{
		ID1:       id1,
		ID2:       id2,
		Reason:    reason,
		CreatedAt: time.Now(),
	}
	g.connections = append(g.connections, conn)
}

// GetConnectionsForEntity returns all connections for a given entity ID
func (g *InMemoryGraph) GetConnectionsForEntity(entityID string) []*Connection {
	g.mu.RLock()
	defer g.mu.RUnlock()

	connections := make([]*Connection, 0, len(g.connections))
	for _, conn := range g.connections {
		if conn.ID1 == entityID || conn.ID2 == entityID {
			connections = append(connections, conn)
		}
	}
	return connections
}

// UpdateBigPicture updates the big picture with new values
func (g *InMemoryGraph) UpdateBigPicture(description, functionalities, technologies string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if description != "" {
		g.bigPicture.Description = description
	}
	if functionalities != "" {
		g.bigPicture.Functionalities = functionalities
	}
	if technologies != "" {
		g.bigPicture.Technologies = technologies
	}
	g.bigPicture.LastUpdated = time.Now().Unix()
}

// UpdateBigPictureWithImpact applies a BigPictureImpact directly (NO confidence check)
func (g *InMemoryGraph) UpdateBigPictureWithImpact(impact *BigPictureImpact) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Validate input
	if impact == nil {
		return fmt.Errorf("impact cannot be nil")
	}
	if impact.Field == "" {
		return fmt.Errorf("impact field cannot be empty")
	}

	switch strings.ToLower(impact.Field) {
	case "description":
		g.bigPicture.Description = impact.Value
	case "functionalities":
		g.bigPicture.Functionalities = impact.Value
	case "technologies":
		g.bigPicture.Technologies = impact.Value
	default:
		return fmt.Errorf("unknown field: %s", impact.Field)
	}

	g.bigPicture.LastUpdated = time.Now().Unix()
	return nil
}

// GetBigPicture returns the current big picture
func (g *InMemoryGraph) GetBigPicture() *BigPicture {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return g.bigPicture
}

// AddOrUpdateSiteMapEntry adds or updates a site map entry
func (g *InMemoryGraph) AddOrUpdateSiteMapEntry(entry *SiteMapEntry) string {
	g.mu.Lock()
	defer g.mu.Unlock()

	if entry.ID == "" {
		// Generate ID from URL and method
		entry.ID = fmt.Sprintf("smap-%s-%s", entry.Method, fmt.Sprintf("%x", entry.URL))
	}

	g.siteMap[entry.ID] = entry
	return entry.ID
}

// GetSiteMapEntry retrieves a site map entry by ID
func (g *InMemoryGraph) GetSiteMapEntry(id string) (*SiteMapEntry, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	entry, ok := g.siteMap[id]
	if !ok {
		return nil, fmt.Errorf("site map entry not found: %s", id)
	}
	return entry, nil
}

// GetAllSiteMapEntries returns all site map entries
func (g *InMemoryGraph) GetAllSiteMapEntries() []*SiteMapEntry {
	g.mu.RLock()
	defer g.mu.RUnlock()

	entries := make([]*SiteMapEntry, 0, len(g.siteMap))
	for _, entry := range g.siteMap {
		entries = append(entries, entry)
	}
	return entries
}

// GetAllObservations returns all observations
func (g *InMemoryGraph) GetAllObservations() []*Observation {
	g.mu.RLock()
	defer g.mu.RUnlock()

	observations := make([]*Observation, 0, len(g.observations))
	for _, obs := range g.observations {
		observations = append(observations, obs)
	}
	return observations
}

// GetAllLeads returns all leads
func (g *InMemoryGraph) GetAllLeads() []*Lead {
	g.mu.RLock()
	defer g.mu.RUnlock()

	leads := make([]*Lead, 0, len(g.leads))
	for _, lead := range g.leads {
		leads = append(leads, lead)
	}
	return leads
}

// GetAllConnections returns all connections
func (g *InMemoryGraph) GetAllConnections() []*Connection {
	g.mu.RLock()
	defer g.mu.RUnlock()

	connections := make([]*Connection, len(g.connections))
	copy(connections, g.connections)
	return connections
}
