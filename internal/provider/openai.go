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
	openaiAPIURL = "https://api.openai.com/v1/chat/completions"
	openaiModel  = "gpt-4o-mini"
	openaiEnvKey = "TRIVY_AI_OPENAI_KEY"
)

// OpenAIProvider sends prompts to OpenAI's chat completion API.
// API key read from TRIVY_AI_OPENAI_KEY — never from CLI flags.
type OpenAIProvider struct {
	apiKey    string
	modelName string
	client    *http.Client
}

var _ internal.Provider = (*OpenAIProvider)(nil)

func NewOpenAIProvider(model string) (*OpenAIProvider, error) {
	key := os.Getenv(openaiEnvKey)
	if key == "" {
		return nil, fmt.Errorf("openai provider requires %s environment variable\n  set it with: export %s=sk-...", openaiEnvKey, openaiEnvKey)
	}
	if model == "" { model = openaiModel }
	return &OpenAIProvider{apiKey: key, modelName: model, client: &http.Client{Timeout: 120 * time.Second}}, nil
}

func (o *OpenAIProvider) Name() string   { return "openai" }
func (o *OpenAIProvider) Model() string  { return o.modelName }
func (o *OpenAIProvider) MaxTokens() int { return 128000 }

type openAIRequest struct {
	Model    string          `json:"model"`
	Messages []openAIMessage `json:"messages"`
}
type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type openAIResponse struct {
	Choices []struct {
		Message struct{ Content string `json:"content"` } `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

func (o *OpenAIProvider) Complete(ctx context.Context, msgs []internal.Message) (string, types.Usage, error) {
	om := make([]openAIMessage, len(msgs))
	for i, m := range msgs { om[i] = openAIMessage{Role: m.Role, Content: m.Content} }

	body, _ := json.Marshal(openAIRequest{Model: o.modelName, Messages: om})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, openaiAPIURL, bytes.NewReader(body))
	if err != nil { return "", types.Usage{}, fmt.Errorf("openai: creating request: %w", err) }

	req.Header.Set("Authorization", "Bearer "+o.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(req)
	if err != nil { return "", types.Usage{}, fmt.Errorf("openai: request failed: %w", err) }
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var result openAIResponse
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return "", types.Usage{}, fmt.Errorf("openai: decoding response: %w", err)
	}
	if result.Error != nil {
		return "", types.Usage{}, fmt.Errorf("openai API error (%s): %s", result.Error.Type, result.Error.Message)
	}
	if len(result.Choices) == 0 {
		return "", types.Usage{}, fmt.Errorf("openai: empty response")
	}
	return result.Choices[0].Message.Content,
		types.Usage{PromptTokens: result.Usage.PromptTokens, CompletionTokens: result.Usage.CompletionTokens}, nil
}