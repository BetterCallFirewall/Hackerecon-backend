# 🛡️ Hackerecon

**AI-Powered HTTP Proxy для автоматизированного анализа безопасности веб-приложений**

Hackerecon — это интеллектуальный HTTP/HTTPS прокси-сервер, который использует большие языковые модели (LLM) для автоматического обнаружения уязвимостей в веб-приложениях. Система перехватывает трафик, анализирует его с помощью AI и генерирует структурированные отчёты о найденных проблемах безопасности.

---

## 🎯 Ключевые возможности

- 🔍 **Интеллектуальный анализ** — LLM анализирует HTTP трафик на наличие уязвимостей
- ⚡ **Двухэтапная оптимизация** — быстрая оценка + полный анализ только важных endpoint'ов
- 🧠 **Контекстное понимание** — накопление знаний о структуре и технологиях целевого сайта
- 🎯 **Генерация гипотез** — автоматическое формулирование главных векторов атаки
- 🔌 **Универсальная LLM поддержка** — работает с Gemini, Ollama, LM Studio, OpenAI-compatible API
- 🔄 **Интеграция с Burp Suite** — опциональная пересылка трафика через Burp
- 📊 **REST API + WebSocket** — интеграция с фронтендом для real-time обновлений
- 🛡️ **Wappalyzer-like детекция** — автоматическое обнаружение технологического стека
- 💾 **Умное кэширование** — сокращение нагрузки на LLM на 70-90%

---

## 🚀 Быстрый старт

### Требования

- Go 1.25 или выше
- LLM провайдер (Gemini / Ollama / LM Studio / др.)

### Установка

```bash
# Клонирование репозитория
git clone https://github.com/BetterCallFirewall/Hackerecon.git
cd Hackerecon

# Установка зависимостей
go mod download

# Создание .env файла
cp .env.example .env
```

### Конфигурация

Отредактируйте `.env` файл:

```bash
# Основные настройки прокси
PROXY_LISTEN_ADDR=:8080
PROXY_CERT_FILE=./certs/ca.crt
PORT=8080

# LLM провайдер (вариант 1: Gemini)
LLM_PROVIDER=gemini
LLM_MODEL=gemini-1.5-pro
API_KEY=your-google-api-key

# LLM провайдер (вариант 2: Ollama - локально)
# LLM_PROVIDER=generic
# LLM_FORMAT=ollama
# LLM_BASE_URL=http://localhost:11434
# LLM_MODEL=llama3.1:8b

# Интеграция с Burp Suite (опционально)
BURP_HOST=127.0.0.1
BURP_PORT=8080
```

### Запуск

```bash
go mod tidy

# Или напрямую через Go
go run cmd/main.go cmd/api.go
```

После запуска:
- 🌐 **HTTP Proxy**: `http://localhost:8080`
- 🔒 **HTTPS Proxy**: `https://localhost:8443`
- 📡 **REST API**: `http://localhost:8081`
- 🔌 **WebSocket**: `ws://localhost:8081/ws`

---

## 📋 Использование

### 1. Настройка браузера

Настройте прокси в браузере или Burp Suite:
- **Proxy**: `localhost:8090`

### 2. Перехват трафика

Просто используйте браузер как обычно. Hackerecon автоматически:
- ✅ Перехватывает HTTP/HTTPS запросы
- ✅ Фильтрует статические ресурсы (css, js, images)
- ✅ Анализирует API endpoints и бизнес-логику
- ✅ Обнаруживает уязвимости в реальном времени

## 🏗️ Архитектура

### Двухэтапный анализ

```
┌──────────────────┐
│  HTTP Request    │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Request Filter   │ ◄── Фильтрация статики (70-90% отсеяно)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ URL Normalizer   │ ◄── /profile/123 → /profile/{id}
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Cache Check     │ ◄── Проверка кэша (40-60% hit rate)
└────────┬─────────┘
         │
         ▼
┌─────────────────────────┐
│ Этап 1: URL Analysis    │ ◄── Быстрая оценка (~1 сек)
│ - Suspicious?           │
│ - Confidence            │
│ - Should analyze?       │
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│ Этап 2: Full Analysis   │ ◄── Полный анализ (~3 сек)
│ - Vulnerability types   │     Только для важных URL
│ - Risk level            │
│ - Security checklist    │
└────────┬────────────────┘
         │
         ▼
┌──────────────────┐
│  Report + WS     │ ◄── Отчёт + WebSocket уведомление
└──────────────────┘
```

### Компоненты

- **SecurityProxyWithGenkit** — главный прокси-сервер
- **GenkitSecurityAnalyzer** — AI анализатор безопасности
- **RequestFilter** — умная фильтрация запросов
- **AnalysisCache** — кэширование результатов
- **SiteContextManager** — управление контекстом сайтов
- **TechDetector** — обнаружение технологий
- **HypothesisGenerator** — генерация гипотез об уязвимостях
- **WebsocketManager** — real-time уведомления

---

## 🎯 Обнаруживаемые уязвимости

Hackerecon использует AI для обнаружения широкого спектра уязвимостей:

- 🔴 **SQL Injection** — внедрение SQL кода
- 🔴 **XSS** (Reflected, Stored, DOM-based) — межсайтовый скриптинг
- 🔴 **IDOR** — небезопасные прямые ссылки на объекты
- 🟠 **Authentication Bypass** — обход аутентификации
- 🟠 **Privilege Escalation** — повышение привилегий (вертикальное/горизонтальное)
- 🟠 **SSRF** — серверные запросы от имени сервера
- 🟡 **Path Traversal** — обход директорий
- 🟡 **Information Disclosure** — утечка информации
- 🟡 **Broken Access Control** — нарушение контроля доступа
- 🟡 **CSRF** — межсайтовая подделка запроса
- 🔵 **Security Misconfiguration** — небезопасная конфигурация
- 🔵 **Sensitive Data Exposure** — раскрытие чувствительных данных

## 🧪 Пример вывода

### Vulnerability Report

```json
{
  "id": "vuln_12345",
  "timestamp": "2024-01-15T10:30:00Z",
  "analysis_result": {
    "has_vulnerability": true,
    "risk_level": "high",
    "vulnerability_types": ["SQL Injection", "Information Disclosure"],
    "ai_comment": "Обнаружена потенциальная SQL-инъекция в параметре 'id'. База данных PostgreSQL возвращает подробные сообщения об ошибках, что подтверждает уязвимость.",
    "confidence_score": 0.85,
    "security_checklist": [
      {
        "action": "Тест SQL инъекции",
        "description": "Попробуйте добавить одинарную кавычку в параметр id",
        "expected": "Ошибка парсинга SQL или изменение поведения"
      }
    ],
    "identified_user_role": "authenticated_user",
    "extracted_secrets": [
      {
        "type": "database_error",
        "value": "pq: syntax error at or near...",
        "confidence": 0.9
      }
    ]
  }
}
```

### Security Hypothesis

```json
{
  "id": "hyp_001",
  "title": "Vertical Privilege Escalation via API",
  "description": "Админские endpoints доступны обычным пользователям без проверки ролей",
  "attack_vector": "Privilege Escalation",
  "target_urls": ["/api/v1/admin/users", "/api/v1/admin/settings"],
  "attack_sequence": [
    {
      "step": 1,
      "action": "Аутентифицироваться как обычный user",
      "expected": "JWT токен с role='user'"
    },
    {
      "step": 2,
      "action": "Запрос к /api/v1/admin/users с user токеном",
      "expected": "200 OK (уязвимость) или 403 Forbidden (защищено)"
    }
  ],
  "confidence": 0.85,
  "impact": "critical",
  "effort": "low"
}
```

---

## 🛠️ Разработка

### Структура проекта

```
Hackerecon/
├── cmd/                    # Точки входа
│   ├── main.go            # Главный сервер (прокси + анализ)
│   └── api.go             # REST API сервер
├── internal/
│   ├── config/            # Конфигурация
│   ├── driven/            # Прокси и анализатор
│   │   ├── analyzer.go    # AI анализатор безопасности
│   │   ├── http.go        # HTTP/HTTPS прокси
│   │   ├── hypothesis.go  # Генерация гипотез
│   │   ├── cache.go       # Кэширование
│   │   └── ...
│   ├── llm/               # LLM интеграция
│   │   ├── provider.go    # Интерфейс провайдера
│   │   ├── generic.go     # Универсальный HTTP провайдер
│   │   ├── gemini.go      # Gemini провайдер
│   │   └── prompt.go      # Промпты для LLM
│   ├── models/            # Модели данных
│   │   ├── vulnerabilities.go
│   │   ├── site_context.go
│   │   └── ...
│   ├── utils/             # Утилиты
│   │   ├── request_filter.go
│   │   ├── url_normalizer.go
│   │   └── tech_detector.go
│   └── websocket/         # WebSocket hub
└── docs/                  # Документация
```

### Сборка
```bash
go mod tidy
go run cmd/main.go
```

---

## 🤝 Вклад в проект

Мы приветствуем вклад в развитие проекта! Пожалуйста:

1. Форкните репозиторий
2. Создайте feature branch (`git checkout -b feature/AmazingFeature`)
3. Закоммитьте изменения (`git commit -m 'Add some AmazingFeature'`)
4. Запушьте в branch (`git push origin feature/AmazingFeature`)
5. Откройте Pull Request

---

## 🔒 Безопасность

**⚠️ ВАЖНО**: Этот инструмент предназначен **исключительно для легального тестирования безопасности** приложений, на которые у вас есть разрешение. Использование для несанкционированного доступа к системам является **незаконным**.

---

## 🗺️ Roadmap

- [ ] Интеграция с популярными vulnerability databases (CVE, OWASP)
- [ ] Использование нескольких LLM для создания разных агентов
- [ ] Добавление возможности использовать существующие утилиты (nmap, sqlmap, etc.)
- [ ] Docker образ для быстрого развертывания
- [ ] Добавление чата для интерактивного взаимодействия с LLM
