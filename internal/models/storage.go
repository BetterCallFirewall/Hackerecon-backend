package models

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

const (
	DefaultMaxObservations   = 1000 // Default limit for observations
	DefaultMaxSiteMapEntries = 500  // Default limit for site map entries
	DefaultMaxRawBuffer      = 500  // Default limit for raw observation buffer
)

// ═══════════════════════════════════════════════════════════════════════════════
// Global InMemoryGraph Reference for Tool Access
// ═══════════════════════════════════════════════════════════════════════════════

// Global in-memory graph reference for tool handlers
// Used by getExchange tool to retrieve HTTP exchanges
var (
	globalGraph *InMemoryGraph
	globalMutex sync.RWMutex
)

// SetGlobalInMemoryGraph sets the global InMemoryGraph reference
// Must be called during analyzer initialization before any tool calls
func SetGlobalInMemoryGraph(graph *InMemoryGraph) {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	globalGraph = graph
}

// GetGlobalInMemoryGraph returns the current global InMemoryGraph reference
func GetGlobalInMemoryGraph() *InMemoryGraph {
	globalMutex.RLock()
	defer globalMutex.RUnlock()
	return globalGraph
}

// ═══════════════════════════════════════════════════════════════════════════════
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

	// IMPORTANT FIX #1: Configurable limit to prevent unbounded memory growth
	maxObservations   int
	maxSiteMapEntries int

	// Raw observation buffer for Analyst (3-phase flow)
	rawObservations []Observation
	rawMu           sync.Mutex
	maxRawBuffer    int // Configurable limit to prevent unbounded raw buffer growth
}

// NewInMemoryGraph creates a new in-memory graph
// IMPORTANT FIX #1: Initialize with configurable max observations limit (default: 1000)
// IMPORTANT FIX #2: Initialize with configurable max site map entries limit (default: 500)
// IMPORTANT FIX #3: Initialize with configurable max raw buffer limit (default: 500)
func NewInMemoryGraph() *InMemoryGraph {
	return &InMemoryGraph{
		exchanges:         make(map[string]*HTTPExchange),
		observations:      make(map[string]*Observation),
		leads:             make(map[string]*Lead),
		connections:       make([]*Connection, 0),
		siteMap:           make(map[string]*SiteMapEntry),
		bigPicture:        &BigPicture{},
		maxObservations:   DefaultMaxObservations,
		maxSiteMapEntries: DefaultMaxSiteMapEntries,
		maxRawBuffer:      DefaultMaxRawBuffer,
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
// IMPORTANT FIX #1: Prune oldest observation if limit exceeded (FIFO)
func (g *InMemoryGraph) AddObservation(observation *Observation) string {
	g.mu.Lock()
	defer g.mu.Unlock()

	// IMPORTANT FIX #1: Prune oldest observation if limit exceeded (FIFO)
	// This prevents unbounded memory growth during long-running sessions
	if len(g.observations) >= g.maxObservations {
		g.pruneOldestObservation()
	}

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
	sort.Slice(
		observations, func(i, j int) bool {
			return observations[i].CreatedAt.After(observations[j].CreatedAt)
		},
	)

	// Return top n
	if n > len(observations) {
		n = len(observations)
	}
	return observations[:n]
}

// GetObservationsForLead returns all observations associated with a lead
// Updated for many-to-many relationship: uses connections instead of ObservationID
func (g *InMemoryGraph) GetObservationsForLead(leadID string) []*Observation {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// Find all connections that involve this lead
	var observationIDs []string
	for _, conn := range g.connections {
		if conn.From == leadID {
			observationIDs = append(observationIDs, conn.To)
		} else if conn.To == leadID {
			observationIDs = append(observationIDs, conn.From)
		}
	}

	if len(observationIDs) == 0 {
		return []*Observation{}
	}

	// Collect all connected observations
	observations := make([]*Observation, 0, len(observationIDs))
	for _, obsID := range observationIDs {
		if obs, ok := g.observations[obsID]; ok {
			observations = append(observations, obs)
		}
	}

	return observations
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
func (g *InMemoryGraph) AddConnection(from, to, reason string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.connectionCount++
	conn := &Connection{
		From:      from,
		To:        to,
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
		if conn.From == entityID || conn.To == entityID {
			connections = append(connections, conn)
		}
	}
	return connections
}

// UpdateBigPicture updates the big picture with new description
func (g *InMemoryGraph) UpdateBigPicture(description string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if description != "" {
		g.bigPicture.Description = description
	}
}

// UpdateBigPictureWithImpact applies a BigPictureImpact directly (NO confidence check)
func (g *InMemoryGraph) UpdateBigPictureWithImpact(impact *BigPictureImpact) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Validate input
	if impact == nil {
		return fmt.Errorf("impact cannot be nil")
	}

	// Only update description field
	if impact.Value != "" {
		g.bigPicture.Description = impact.Value
	}

	return nil
}

// GetBigPicture returns the current big picture
func (g *InMemoryGraph) GetBigPicture() *BigPicture {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return g.bigPicture
}

// AddOrUpdateSiteMapEntry adds or updates a site map entry
// IMPORTANT FIX #2: Prune oldest entry if limit exceeded (FIFO)
func (g *InMemoryGraph) AddOrUpdateSiteMapEntry(entry *SiteMapEntry) string {
	g.mu.Lock()
	defer g.mu.Unlock()

	if entry.ID == "" {
		// Generate ID from URL and method
		entry.ID = fmt.Sprintf("smap-%s-%s", entry.Method, fmt.Sprintf("%x", entry.URL))
	}

	// Set CreatedAt if this is a new entry (not an update)
	if existing, found := g.siteMap[entry.ID]; !found {
		// New entry - set CreatedAt
		if entry.CreatedAt.IsZero() {
			entry.CreatedAt = time.Now()
		}
	} else {
		// Update - preserve original CreatedAt
		entry.CreatedAt = existing.CreatedAt
	}

	g.siteMap[entry.ID] = entry

	if len(g.siteMap) > g.maxSiteMapEntries {
		g.pruneOldestSiteMapEntry()
	}

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

// GetRecentLeads returns the N most recent leads (newest first)
// Added for lead deduplication in detective flow (many-to-many relationship)
func (g *InMemoryGraph) GetRecentLeads(limit int) []Lead {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if len(g.leads) == 0 {
		return []Lead{}
	}

	leads := make([]Lead, 0, len(g.leads))
	for _, lead := range g.leads {
		leads = append(leads, *lead)
	}

	// Sort by CreatedAt (newest first)
	sort.Slice(
		leads, func(i, j int) bool {
			return leads[i].CreatedAt.After(leads[j].CreatedAt)
		},
	)

	if len(leads) > limit {
		leads = leads[:limit]
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

// pruneOldestObservation removes the oldest observation from the graph
// IMPORTANT FIX #1: Helper method for FIFO pruning to prevent unbounded memory growth
// NOTE: This must be called while holding the write lock (mu.Lock)
func (g *InMemoryGraph) pruneOldestObservation() {
	if len(g.observations) == 0 {
		return
	}

	// Find oldest observation by CreatedAt
	var oldestID string
	var oldestTime time.Time
	first := true

	for id, obs := range g.observations {
		if first || obs.CreatedAt.Before(oldestTime) {
			oldestID = id
			oldestTime = obs.CreatedAt
			first = false
		}
	}

	// Remove oldest observation
	if oldestID != "" {
		delete(g.observations, oldestID)
	}
}

// pruneOldestSiteMapEntry removes the oldest site map entry from the graph
// IMPORTANT FIX #2: Helper method for FIFO pruning to prevent unbounded memory growth
// NOTE: This must be called while holding the write lock (mu.Lock)
func (g *InMemoryGraph) pruneOldestSiteMapEntry() {
	if len(g.siteMap) == 0 {
		return
	}

	// Find oldest site map entry by CreatedAt
	var oldestID string
	var oldestTime time.Time
	first := true

	for id, entry := range g.siteMap {
		if first || entry.CreatedAt.Before(oldestTime) {
			oldestID = id
			oldestTime = entry.CreatedAt
			first = false
		}
	}

	// Remove oldest site map entry
	if oldestID != "" {
		delete(g.siteMap, oldestID)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Raw Observation Buffer (3-Phase Flow)
// ═══════════════════════════════════════════════════════════════════════════════

// AddRawObservation adds a raw observation from Analyst
// IMPORTANT FIX #3: Prune oldest raw observation if limit exceeded (FIFO)
func (g *InMemoryGraph) AddRawObservation(observation *Observation) string {
	g.rawMu.Lock()
	defer g.rawMu.Unlock()

	// IMPORTANT FIX #3: Prune oldest raw observation if limit exceeded (FIFO)
	// This prevents unbounded memory growth during long-running sessions
	if len(g.rawObservations) >= g.maxRawBuffer {
		// Remove oldest (first element) - FIFO
		g.rawObservations = g.rawObservations[1:]
	}

	g.observationCount++
	id := fmt.Sprintf("raw-%d", g.observationCount)

	stored := *observation
	stored.ID = id
	if stored.CreatedAt.IsZero() {
		stored.CreatedAt = time.Now()
	}

	g.rawObservations = append(g.rawObservations, stored)
	return id
}

// GetAndClearRawBuffer returns all raw observations and clears the buffer atomically
func (g *InMemoryGraph) GetAndClearRawBuffer() []Observation {
	g.rawMu.Lock()
	defer g.rawMu.Unlock()

	result := make([]Observation, len(g.rawObservations))
	copy(result, g.rawObservations)

	g.rawObservations = []Observation{} // Clear buffer

	return result
}
