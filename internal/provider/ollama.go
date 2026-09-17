package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jp2op/trivy-ai/internal"
	"github.com/jp2op/trivy-ai/pkg/types"
)

// OllamaProvider sends prompts to a locally running Ollama instance.
// It supports any model available in Ollama (llama3, mistral, codellama, etc.).
type OllamaProvider struct {
	// BaseURL is the Ollama API base URL (default: http://localhost:11434).
	BaseURL string
	// ModelName is the Ollama model to use (default: llama3).
	ModelName string
	// client is the HTTP client used for API calls.
	client *http.Client
}

// Compile-time check: OllamaProvider must satisfy the Provider interface.
var _ internal.Provider = (*OllamaProvider)(nil)

// NewOllamaProvider creates a new OllamaProvider with the given base URL and model.
func NewOllamaProvider(baseURL, model string) *OllamaProvider {
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	if model == "" {
		model = "llama3"
	}
	return &OllamaProvider{
		BaseURL:   baseURL,
		ModelName: model,
		client:    &http.Client{Timeout: 120 * time.Second},
	}
}

// Name returns "ollama".
func (o *OllamaProvider) Name() string { return "ollama" }

// Model returns the active Ollama model name.
func (o *OllamaProvider) Model() string { return o.ModelName }

// MaxTokens returns a conservative default context window.
// The actual limit depends on the model loaded in Ollama.
func (o *OllamaProvider) MaxTokens() int { return 4096 }

// ollamaRequest is the request body for the Ollama /api/chat endpoint.
type ollamaRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
}

type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ollamaResponse is the response from the Ollama /api/chat endpoint.
type ollamaResponse struct {
	Message ollamaMessage `json:"message"`
	Done    bool          `json:"done"`
	Error   string        `json:"error,omitempty"`
}

// Complete sends messages to Ollama and returns the full response.
func (o *OllamaProvider) Complete(ctx context.Context, msgs []internal.Message) (string, types.Usage, error) {
	ollamaMsgs := make([]ollamaMessage, len(msgs))
	for i, m := range msgs {
		ollamaMsgs[i] = ollamaMessage{Role: m.Role, Content: m.Content}
	}

	reqBody := ollamaRequest{
		Model:    o.ModelName,
		Messages: ollamaMsgs,
		Stream:   false,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", types.Usage{}, fmt.Errorf("ollama: marshaling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.BaseURL+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return "", types.Usage{}, fmt.Errorf("ollama: creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		return "", types.Usage{}, fmt.Errorf(
			"ollama: request failed — is Ollama running? Start it with: ollama serve\n  error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", types.Usage{}, fmt.Errorf(
			"ollama: unexpected status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", types.Usage{}, fmt.Errorf("ollama: decoding response: %w", err)
	}

	if result.Error != "" {
		return "", types.Usage{}, fmt.Errorf("ollama: model error: %s", result.Error)
	}

	// Ollama doesn't return token counts in the chat endpoint by default.
	// Estimate based on character count (1 token ≈ 4 chars).
	usage := types.Usage{
		PromptTokens:     estimateTokens(msgs),
		CompletionTokens: len(result.Message.Content) / 4,
	}

	return result.Message.Content, usage, nil
}
