package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/jp2op/trivy-ai/internal"
	"github.com/jp2op/trivy-ai/pkg/types"
)

const (
	geminiModel    = "gemini-1.5-flash"
	geminiRegion   = "us-central1"
	geminiEnvKey   = "TRIVY_AI_GEMINI_KEY"
	geminiProject  = "TRIVY_AI_GCP_PROJECT"
)

// GeminiProvider sends prompts to Google Vertex AI Gemini models.
// Supports two auth methods:
//   1. TRIVY_AI_GEMINI_KEY env var (API key from Google AI Studio)
//   2. Application Default Credentials via gcloud auth application-default login
type GeminiProvider struct {
	projectID string
	region    string
	modelName string
	apiKey    string // optional — if empty, uses ADC token
	client    *http.Client
}

var _ internal.Provider = (*GeminiProvider)(nil)

// NewGeminiProvider creates a GeminiProvider.
// projectID is required. region defaults to us-central1.
func NewGeminiProvider(projectID, region, model string) (*GeminiProvider, error) {
	if projectID == "" {
		projectID = os.Getenv(geminiProject)
	}
	if projectID == "" {
		return nil, fmt.Errorf(
			"gemini provider requires a GCP project ID\n" +
			"  set it with: export %s=your-project-id\n" +
			"  or pass --gcp-project flag", geminiProject)
	}
	if region == "" {
		region = geminiRegion
	}
	if model == "" {
		model = geminiModel
	}
	return &GeminiProvider{
		projectID: projectID,
		region:    region,
		modelName: model,
		apiKey:    os.Getenv(geminiEnvKey),
		client:    &http.Client{Timeout: 120 * time.Second},
	}, nil
}

func (g *GeminiProvider) Name() string     { return "gemini" }
func (g *GeminiProvider) Model() string    { return g.modelName }
func (g *GeminiProvider) MaxTokens() int   { return 1000000 } // Gemini 1.5 Flash

// geminiRequest is the Vertex AI generateContent request body.
type geminiRequest struct {
	Contents []geminiContent `json:"contents"`
}

type geminiContent struct {
	Role  string        `json:"role"`
	Parts []geminiPart  `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	UsageMetadata struct {
		PromptTokenCount     int `json:"promptTokenCount"`
		CandidatesTokenCount int `json:"candidatesTokenCount"`
	} `json:"usageMetadata"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Complete sends messages to Vertex AI Gemini and returns the response.
func (g *GeminiProvider) Complete(ctx context.Context, msgs []internal.Message) (string, types.Usage, error) {
	// Build Gemini content format
	contents := make([]geminiContent, 0, len(msgs))
	for _, m := range msgs {
		role := m.Role
		if role == "assistant" {
			role = "model" // Gemini uses "model" not "assistant"
		}
		contents = append(contents, geminiContent{
			Role:  role,
			Parts: []geminiPart{{Text: m.Content}},
		})
	}

	body, err := json.Marshal(geminiRequest{Contents: contents})
	if err != nil {
		return "", types.Usage{}, fmt.Errorf("gemini: marshaling request: %w", err)
	}

	url := fmt.Sprintf(
    	"https://aiplatform.googleapis.com/v1/projects/%s/locations/global/publishers/google/models/%s:generateContent",
    	g.projectID, g.modelName,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", types.Usage{}, fmt.Errorf("gemini: creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Auth: API key takes priority, then ADC token
	if g.apiKey != "" {
		req.Header.Set("x-goog-api-key", g.apiKey)
	} else {
		token, err := getADCToken(ctx)
		if err != nil {
			return "", types.Usage{}, fmt.Errorf(
				"gemini: getting auth token failed\n"+
				"  run: gcloud auth application-default login\n"+
				"  error: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return "", types.Usage{}, fmt.Errorf("gemini: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", types.Usage{}, fmt.Errorf("gemini: reading response: %w", err)
	}

	var result geminiResponse
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return "", types.Usage{}, fmt.Errorf("gemini: decoding response: %w", err)
	}

	if result.Error != nil {
		return "", types.Usage{}, fmt.Errorf("gemini API error (%d): %s",
			result.Error.Code, result.Error.Message)
	}

	if len(result.Candidates) == 0 || len(result.Candidates[0].Content.Parts) == 0 {
		return "", types.Usage{}, fmt.Errorf("gemini: empty response")
	}

	// Collect all text parts
	var text strings.Builder
	for _, part := range result.Candidates[0].Content.Parts {
		text.WriteString(part.Text)
	}

	usage := types.Usage{
		PromptTokens:     result.UsageMetadata.PromptTokenCount,
		CompletionTokens: result.UsageMetadata.CandidatesTokenCount,
	}

	return text.String(), usage, nil
}

// getADCToken retrieves an access token using Application Default Credentials
// by calling gcloud — no extra Go libraries needed.
func getADCToken(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "gcloud", "auth", "application-default", "print-access-token")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("gcloud command failed: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}