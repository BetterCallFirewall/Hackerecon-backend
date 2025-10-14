package llm

type MultiModelAnalyzer struct {
	genkitApp     *genkit.
	geminiModel   ai.Model
	primaryModel  string
	analysisFlows map[string]genkit.Flow
}

func NewMultiModelAnalyzer() {
	g := genkit.Init
}
