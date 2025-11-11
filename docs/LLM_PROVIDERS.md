# 🔌 Подключение разных LLM провайдеров

## 📋 Поддерживаемые провайдеры

### 1. **Gemini (Google)** - Рекомендуется
- ✅ Отличное качество анализа
- ✅ Большой context window (2M токенов)
- ✅ Structured output из коробки
- ✅ Доступная цена

### 2. **Generic HTTP Provider**
Работает с любым HTTP API:
- Ollama (локально)
- LM Studio (локально)
- LocalAI (локально)
- vLLM (облако/локально)
- OpenAI-compatible API

---

## 🚀 Быстрый старт

### Вариант 1: Gemini (по умолчанию)

```bash
# .env
LLM_PROVIDER=gemini
LLM_MODEL=gemini-1.5-pro
API_KEY=your-google-api-key
```

**Получить API ключ:** https://makersuite.google.com/app/apikey

### Вариант 2: Ollama (бесплатно, локально)

1. Установите Ollama: https://ollama.com/download
2. Скачайте модель:
```bash
ollama pull llama3.1:8b
ollama serve
```

3. Настройте .env:
```bash
LLM_PROVIDER=generic
LLM_FORMAT=ollama
LLM_BASE_URL=http://localhost:11434
```

### Вариант 3: LM Studio (GUI для локальных моделей)

1. Установите LM Studio: https://lmstudio.ai/
2. Загрузите модель через GUI
3. Запустите сервер (Server tab → Start Server)

4. Настройте .env:
```bash
LLM_PROVIDER=generic
LLM_FORMAT=openai
LLM_BASE_URL=http://localhost:1234
```

---

## ⚙️ Параметры конфигурации

### Обязательные параметры

| Параметр | Описание | Пример |
|----------|----------|--------|
| `LLM_PROVIDER` | Тип провайдера | `gemini` или `generic` |

### Для Gemini

| Параметр | Описание | Пример |
|----------|----------|--------|
| `LLM_MODEL` | Модель | `gemini-1.5-pro`, `gemini-1.5-flash` |
| `API_KEY` | API ключ Google | `AIza...` |

### Для Generic провайдера

| Параметр | Описание | Пример |
|----------|----------|--------|
| `LLM_BASE_URL` | Базовый URL API | `http://localhost:11434` |
| `LLM_FORMAT` | Формат API | `openai`, `ollama`, `raw` |
| `API_KEY` | API ключ (если нужен) | Опционально |

---

## 🔧 Форматы API

### `openai` - OpenAI-compatible
Работает с:
- LM Studio
- LocalAI
- vLLM (с OpenAI endpoint)
- Text Generation Inference

**Формат запроса:**
```json
{
  "messages": [{"role": "user", "content": "..."}],
  "temperature": 0.2,
  "max_tokens": 2000
}
```

### `ollama` - Ollama API
Работает с Ollama локально

**Формат запроса:**
```json
{
  "model": "llama3.1:8b",
  "prompt": "...",
  "format": "json",
  "stream": false
}
```

### `raw` - Простой JSON
Для custom API

**Формат запроса:**
```json
{
  "prompt": "...",
  "temperature": 0.2,
  "max_tokens": 2000
}
```

---

## 🎯 Рекомендации по выбору модели

### Для production
- **Gemini 1.5 Pro** - лучший баланс качество/цена
- **Claude 3.5 Sonnet** - максимальное качество reasoning (нужен отдельный провайдер)

### Для тестирования
- **Gemini 1.5 Flash** - быстро и дёшево
- **Ollama llama3.1:8b** - бесплатно локально

### Для приватности
- **Ollama** (любая модель) - всё локально
- **LM Studio** - GUI + локально

---

## 📝 Примеры использования в коде

### Создание Gemini провайдера

```go
provider := llm.NewGeminiProvider(genkitApp, "gemini-1.5-pro")
```

### Создание Ollama провайдера

```go
provider := llm.NewOllamaProvider("http://localhost:11434", "llama3.1:8b")
```

### Создание LM Studio провайдера

```go
provider := llm.NewLMStudioProvider("http://localhost:1234")
```

### Создание Generic провайдера

```go
provider := llm.NewGenericProvider(llm.GenericConfig{
    Name:    "my-custom-llm",
    BaseURL: "https://api.example.com",
    APIKey:  "your-key",
    Format:  llm.FormatOpenAI,
})
```

---

## 🐛 Troubleshooting

### Ollama: "connection refused"
```bash
# Убедитесь что Ollama запущен
ollama serve

# Проверьте доступность
curl http://localhost:11434/api/tags
```

### LM Studio: "404 Not Found"
- Убедитесь что сервер запущен (Server tab → Start Server)
- Проверьте порт в UI (обычно 1234)

### Generic: "invalid JSON response"
- Модель может возвращать markdown вместо чистого JSON
- Попробуйте другую модель или улучшите промпт
- Проверьте поддержку JSON mode в вашем API

---

## 💡 Советы по оптимизации

1. **Используйте локальные модели для разработки** - быстрее и бесплатно
2. **Gemini для production** - лучший баланс
3. **Temperature = 0.2** - для стабильного анализа безопасности
4. **Max tokens = 2000** - достаточно для structured output

---

## 🔗 Полезные ссылки

- [Ollama](https://ollama.com/)
- [LM Studio](https://lmstudio.ai/)
- [Gemini API](https://ai.google.dev/)
- [LocalAI](https://localai.io/)
- [vLLM](https://docs.vllm.ai/)
