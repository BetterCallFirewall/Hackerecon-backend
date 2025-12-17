package driven

import (
	"time"
)

// Constants for analysis configuration
const (
	// Content size limits
	maxContentSizeForLLM = 2000
	maxCommentLength     = 200

	// Analysis timeouts
	defaultAnalysisTimeout = 60 * time.Second

	// Site context requirements
	minURLPatternsForHypothesis = 2
)
