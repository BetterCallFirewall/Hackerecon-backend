package llm

type AnalysisResult struct {
	VulnerabilitiesFound bool                   `json:"vulnerabilitiesFound"`
	Findings             []VulnerabilityFinding `json:"findings"`
	OverallRisk          string                 `json:"overall_risk"`
	PentesterActions     []string               `json:"pentester_actions"`
}

type VulnerabilityFinding struct {
	Type           string `json:"type"`
	Severity       string `json:"severity"`
	Location       string `json:"location"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
}
