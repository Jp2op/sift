package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/jp2op/trivy-ai/internal"
	"github.com/jp2op/trivy-ai/pkg/types"
)

const (
	anthropicAPIURL     = "https://api.anthropic.com/v1/messages"
	anthropicAPIVersion = "2023-06-01"
	anthropicModel      = "claude-sonnet-4-6"
	anthropicEnvKey     = "TRIVY_AI_ANTHROPIC_KEY"
)

// AnthropicProvider sends prompts to Anthropic's Claude API.
// API key read from TRIVY_AI_ANTHROPIC_KEY — never from CLI flags.
type AnthropicProvider struct {
	apiKey    string
	modelName string
	client    *http.Client
}

var _ internal.Provider = (*AnthropicProvider)(nil)

func NewAnthropicProvider(model string) (*AnthropicProvider, error) {
	key := os.Getenv(anthropicEnvKey)
	if key == "" {
		return nil, fmt.Errorf("anthropic provider requires %s environment variable\n  set it with: export %s=sk-ant-...", anthropicEnvKey, anthropicEnvKey)
	}
	if model == "" { model = anthropicModel }
	return &AnthropicProvider{apiKey: key, modelName: model, client: &http.Client{Timeout: 120 * time.Second}}, nil
}

func (a *AnthropicProvider) Name() string     { return "anthropic" }
func (a *AnthropicProvider) Model() string    { return a.modelName }
func (a *AnthropicProvider) MaxTokens() int   { return 200000 }

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	Messages  []anthropicMessage `json:"messages"`
}
type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (a *AnthropicProvider) Complete(ctx context.Context, msgs []internal.Message) (string, types.Usage, error) {
	am := make([]anthropicMessage, len(msgs))
	for i, m := range msgs { am[i] = anthropicMessage{Role: m.Role, Content: m.Content} }

	body, _ := json.Marshal(anthropicRequest{Model: a.modelName, MaxTokens: 1024, Messages: am})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, anthropicAPIURL, bytes.NewReader(body))
	if err != nil { return "", types.Usage{}, fmt.Errorf("anthropic: creating request: %w", err) }

	req.Header.Set("x-api-key", a.apiKey)
	req.Header.Set("anthropic-version", anthropicAPIVersion)
	req.Header.Set("content-type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil { return "", types.Usage{}, fmt.Errorf("anthropic: request failed: %w", err) }
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var result anthropicResponse
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return "", types.Usage{}, fmt.Errorf("anthropic: decoding response: %w", err)
	}
	if result.Error != nil {
		return "", types.Usage{}, fmt.Errorf("anthropic API error (%s): %s", result.Error.Type, result.Error.Message)
	}

	var text string
	for _, block := range result.Content {
		if block.Type == "text" { text += block.Text }
	}
	return text, types.Usage{PromptTokens: result.Usage.InputTokens, CompletionTokens: result.Usage.OutputTokens}, nil
}