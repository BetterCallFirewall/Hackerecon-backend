package web

import (
	"encoding/json"
	"net/http"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

func (s *Server) GetAnalysis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
		return
	}

	allAnalyses := s.broker.Subscribe(models.LLMTopic)

	res := make([]models.SecurityAnalysisResponse, len(allAnalyses))
	for i := 0; i < len(allAnalyses); i++ {
		analysisResponse := <-allAnalyses
		res = append(res, analysisResponse)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	json.NewEncoder(w).Encode(res)
}
