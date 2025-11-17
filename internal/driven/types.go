package driven

import (
	"time"
)

// Constants for analysis configuration
const (
	// Content size limits
	maxContentSizeForLLM     = 2000
	maxCommentLength         = 200
	maxContextLength         = 100
	maxFunctionContextLength = 200

	// Secret detection
	minSecretLength = 8

	// Cache settings
	defaultCacheExpiry     = 10 * time.Minute
	defaultCacheSizeLimit  = 1000
	minCacheSizeForCleanup = 500
	cacheRetentionRatio    = 0.5

	// Analysis timeouts
	defaultAnalysisTimeout = 30 * time.Second

	// Site context requirements
	minURLPatternsForHypothesis = 3
)
