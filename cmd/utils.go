package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/BetterCallFirewall/Hackerecon/internal/driven"
)

func startGenkitReportServer(analyzer *driven.GenkitSecurityAnalyzer) {
	http.HandleFunc(
		"/api/reports", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")

			reports := analyzer.GetReports()
			json.NewEncoder(w).Encode(reports)
		},
	)

	http.HandleFunc(
		"/api/high-risk", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")

			highRiskReports := analyzer.GetHighRiskReports()
			json.NewEncoder(w).Encode(highRiskReports)
		},
	)

	http.HandleFunc(
		"/api/stats", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")

			stats := analyzer.GetSummaryStats()
			json.NewEncoder(w).Encode(stats)
		},
	)

	http.HandleFunc(
		"/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(getGenkitDashboardHTML()))
		},
	)

	log.Println("📊 Genkit Report Server запущен на http://localhost:8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

func getGenkitDashboardHTML() string {
	return `<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔒 Security Proxy с Genkit AI</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333; min-height: 100vh;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 2rem; }
        .header { text-align: center; margin-bottom: 3rem; }
        .header h1 { color: white; font-size: 3rem; margin-bottom: 1rem; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }
        .header p { color: rgba(255,255,255,0.9); font-size: 1.2rem; }

        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
        .stat-card { 
            background: rgba(255,255,255,0.95); padding: 1.5rem; border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1); backdrop-filter: blur(10px);
            text-align: center; transition: transform 0.3s ease;
        }
        .stat-card:hover { transform: translateY(-5px); }
        .stat-number { font-size: 2.5rem; font-weight: bold; margin-bottom: 0.5rem; }
        .stat-label { color: #666; text-transform: uppercase; font-size: 0.9rem; letter-spacing: 1px; }

        .critical { color: #e74c3c; } .high { color: #e67e22; }
        .medium { color: #f39c12; } .low { color: #27ae60; }
        .info { color: #3498db; } .success { color: #2ecc71; }

        .reports-section { 
            background: rgba(255,255,255,0.95); border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1); backdrop-filter: blur(10px);
            overflow: hidden; margin-bottom: 2rem;
        }
        .section-header { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; padding: 1.5rem; font-size: 1.3rem; font-weight: 600;
        }

        .report-item { padding: 1.5rem; border-bottom: 1px solid #e9ecef; }
        .report-item:hover { background: #f8f9fa; }
        .report-item:last-child { border-bottom: none; }

        .report-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
        .report-url { font-weight: 600; color: #2c3e50; flex: 1; }
        .risk-badge { 
            padding: 0.5rem 1rem; border-radius: 25px; font-size: 0.8rem;
            font-weight: 600; text-transform: uppercase; margin-left: 1rem;
        }
        .risk-critical { background: #e74c3c; color: white; }
        .risk-high { background: #e67e22; color: white; }
        .risk-medium { background: #f39c12; color: white; }
        .risk-low { background: #27ae60; color: white; }

        .ai-comment { 
            background: #f8f9fa; padding: 1rem; border-radius: 8px; margin: 1rem 0;
            border-left: 4px solid #3498db; font-style: italic;
        }

        .checklist { margin: 1rem 0; }
        .checklist-item { 
            background: white; padding: 1rem; margin: 0.5rem 0; border-radius: 8px;
            border-left: 4px solid #3498db;
        }
        .checklist-title { font-weight: 600; color: #2c3e50; margin-bottom: 0.5rem; }
        .checklist-desc { color: #666; font-size: 0.9rem; }

        .secrets-found { 
            background: #fff3cd; border: 1px solid #ffeaa7; padding: 1rem;
            border-radius: 8px; margin: 1rem 0;
        }
        .secret-item { 
            background: #ffe8e8; padding: 0.5rem; margin: 0.3rem 0;
            border-radius: 4px; font-family: monospace; font-size: 0.8rem;
        }

        .refresh-btn { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; border: none; padding: 1rem 2rem; border-radius: 25px;
            cursor: pointer; font-size: 1rem; transition: transform 0.2s ease;
        }
        .refresh-btn:hover { transform: scale(1.05); }

        .loading { text-align: center; padding: 3rem; color: #666; }
        .no-data { text-align: center; padding: 3rem; color: #999; }

        @media (max-width: 768px) {
            .container { padding: 1rem; }
            .header h1 { font-size: 2rem; }
            .stats-grid { grid-template-columns: 1fr; }
            .report-header { flex-direction: column; align-items: flex-start; }
            .risk-badge { margin: 0.5rem 0 0 0; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Proxy Dashboard</h1>
            <p>Анализ уязвимостей веб-трафика с помощью Genkit AI</p>
        </div>

        <div class="stats-grid" id="statsGrid">
            <div class="stat-card">
                <div class="stat-number info" id="totalReports">0</div>
                <div class="stat-label">Всего анализов</div>
            </div>
            <div class="stat-card">
                <div class="stat-number critical" id="vulnerableRequests">0</div>
                <div class="stat-label">С уязвимостями</div>
            </div>
            <div class="stat-card">
                <div class="stat-number critical" id="criticalRisks">0</div>
                <div class="stat-label">Критические</div>
            </div>
            <div class="stat-card">
                <div class="stat-number high" id="highRisks">0</div>
                <div class="stat-label">Высокий риск</div>
            </div>
            <div class="stat-card">
                <div class="stat-number medium" id="mediumRisks">0</div>
                <div class="stat-label">Средний риск</div>
            </div>
            <div class="stat-card">
                <div class="stat-number success" id="secretsFound">0</div>
                <div class="stat-label">Секретов найдено</div>
            </div>
            <div class="stat-card">
                <div class="stat-number info" id="avgConfidence">0.0</div>
                <div class="stat-label">Средняя уверенность</div>
            </div>
        </div>

        <div class="reports-section">
            <div class="section-header">
                🤖 Отчеты анализа уязвимостей с AI комментариями
                <button class="refresh-btn" onclick="loadData()" style="float: right;">🔄 Обновить</button>
            </div>
            <div id="reportsContainer">
                <div class="loading">Загрузка отчетов...</div>
            </div>
        </div>
    </div>

    <script>
        async function loadStats() {
            try {
                const response = await fetch('/api/stats');
                const data = await response.json();

                document.getElementById('totalReports').textContent = data.total_reports || 0;
                document.getElementById('vulnerableRequests').textContent = data.vulnerable_requests || 0;
                document.getElementById('criticalRisks').textContent = data.critical_risks || 0;
                document.getElementById('highRisks').textContent = data.high_risks || 0;
                document.getElementById('mediumRisks').textContent = data.medium_risks || 0;
                document.getElementById('secretsFound').textContent = data.secrets_found || 0;
                document.getElementById('avgConfidence').textContent = (data.avg_confidence || 0).toFixed(2);
            } catch (error) {
                console.error('Ошибка загрузки статистики:', error);
            }
        }

        async function loadReports() {
            try {
                const response = await fetch('/api/reports');
                const reports = await response.json();

                const container = document.getElementById('reportsContainer');

                if (!reports || reports.length === 0) {
                    container.innerHTML = '<div class="no-data">📭 Пока нет отчетов для отображения</div>';
                    return;
                }

                let html = '';
                reports.slice(-10).reverse().forEach(report => {
                    const result = report.analysis_result;
                    const riskClass = getRiskClass(result.risk_level);
                    const riskLabel = getRiskLabel(result.risk_level);
                    const timestamp = new Date(report.timestamp).toLocaleString('ru-RU');

                    html += \
	<div class="report-item">
	<div class="report-header">
	<span class="report-url">\${result.url}</span>
	<span class="risk-badge risk-\${riskClass}">\${riskLabel}</span>
	</div>

	<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin: 1rem 0;">
	<div><strong>Время:</strong> \${timestamp}</div>
	<div><strong>Модель:</strong> \${report.model_used}</div>
	<div><strong>Время анализа:</strong> \${(report.processing_time / 1000000).toFixed(0)}ms</div>
	<div><strong>Уверенность:</strong> \${(result.confidence_score * 100).toFixed(1)}%</div>
	</div>

	\${result.has_vulnerability ? \
                                <div class="ai-comment">
                                    <strong>🤖 AI Анализ:</strong> \${result.ai_comment}
                                </div>

                                \${result.security_checklist && result.security_checklist.length > 0 ? \
	<div class="checklist">
	<strong>✅ Чеклист для ручной проверки:</strong>
	\${result.security_checklist.map(check => \
                                            <div class="checklist-item">
                                                <div class="checklist-title">\${check.check_name} (\${check.priority})</div>
                                                <div class="checklist-desc">\${check.description}</div>
                                                <div class="checklist-desc"><em>Инструкция:</em> \${check.instructions}</div>
                                            </div>
                                        \).join('')}
	</div>
	\ : ''}

                                \${result.extracted_secrets && result.extracted_secrets.length > 0 ? \
	<div class="secrets-found">
	<strong>🔐 Найдены секреты:</strong>
	\${result.extracted_secrets.map(secret => \
                                            <div class="secret-item">
                                                <strong>\${secret.type}</strong>: \${secret.value}
                                                <em>(уверенность: \${(secret.confidence * 100).toFixed(0)}%)</em>
                                            </div>
                                        \).join('')}
	</div>
	\ : ''}

                                \${result.vulnerability_types && result.vulnerability_types.length > 0 ? \
	<div><strong>🚨 Типы уязвимостей:</strong> \${result.vulnerability_types.join(', ')}</div>
	\ : ''}

                                \${result.recommendations && result.recommendations.length > 0 ? \
	<div style="margin-top: 1rem;"><strong>💡 Рекомендации:</strong>
	<ul>\${result.recommendations.map(rec => \<li>\${rec}</li>\).join('')}</ul>
	</div>
	\ : ''}
                            \ : \
                                <div style="color: #27ae60; font-weight: 600;">✅ Уязвимости не обнаружены</div>
                                <div class="ai-comment"><strong>🤖 AI Анализ:</strong> \${result.ai_comment}</div>
                            \}
	</div>
	\;
                });

                container.innerHTML = html;
            } catch (error) {
                console.error('Ошибка загрузки отчетов:', error);
                document.getElementById('reportsContainer').innerHTML = 
                    '<div class="no-data">❌ Ошибка загрузки данных</div>';
            }
        }

        function getRiskClass(level) {
            const riskMap = { 'critical': 'critical', 'high': 'high', 'medium': 'medium', 'low': 'low' };
            return riskMap[level] || 'low';
        }

        function getRiskLabel(level) {
            const labelMap = { 'critical': 'Критический', 'high': 'Высокий', 'medium': 'Средний', 'low': 'Низкий' };
            return labelMap[level] || 'Неизвестный';
        }

        function loadData() {
            loadStats();
            loadReports();
        }

        // Автоматическое обновление каждые 10 секунд
        setInterval(loadData, 10000);

        // Первоначальная загрузка
        loadData();
    </script>
</body>
</html>`
}
