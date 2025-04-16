package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey2(t *testing.T) {
	tests := []struct {
		name           string
		headers        http.Header
		wantAPIKey     string
		wantErr        error
		wantErrMessage string
	}{
		{
			name:           "No Authorization Header",
			headers:        http.Header{},
			wantAPIKey:     "",
			wantErr:        ErrNoAuthHeaderIncluded,
			wantErrMessage: "no authorization header included",
		},
		{
			name: "Empty Authorization Header",
			headers: http.Header{
				"Authorization": []string{""},
			},
			wantAPIKey:     "",
			wantErr:        ErrNoAuthHeaderIncluded,
			wantErrMessage: "no authorization header included",
		},
		{
			name: "Missing ApiKey Prefix",
			headers: http.Header{
				"Authorization": []string{"invalid-key"},
			},
			wantAPIKey:     "",
			wantErr:        nil,
			wantErrMessage: "malformed authorization header",
		},
		{
			name: "Valid API Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey test-key-123"},
			},
			wantAPIKey:     "test-key-123",
			wantErr:        nil,
			wantErrMessage: "",
		},
		{
			name: "API Key with Spaces",
			headers: http.Header{
				"Authorization": []string{"ApiKey test key with spaces"},
			},
			wantAPIKey:     "test key with spaces",
			wantErr:        nil,
			wantErrMessage: "",
		},
		{
			name: "Multiple Authorization Headers",
			headers: http.Header{
				"Authorization": []string{"ApiKey first-key", "ApiKey second-key"},
			},
			wantAPIKey:     "first-key",
			wantErr:        nil,
			wantErrMessage: "",
		},
		{
			name: "Case Insensitive Header Name",
			headers: http.Header{
				"authorization": []string{"ApiKey test-key"},
			},
			wantAPIKey:     "test-key",
			wantErr:        nil,
			wantErrMessage: "",
		},
		{
			name: "Empty API Key Value",
			headers: http.Header{
				"Authorization": []string{"ApiKey "},
			},
			wantAPIKey:     "",
			wantErr:        nil,
			wantErrMessage: "malformed authorization header",
		},
		{
			name: "Special Characters in API Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey !@#$%^&*()"},
			},
			wantAPIKey:     "!@#$%^&*()",
			wantErr:        nil,
			wantErrMessage: "",
		},
		{
			name: "Long API Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey " + string(make([]byte, 1000))},
			},
			wantAPIKey:     string(make([]byte, 1000)),
			wantErr:        nil,
			wantErrMessage: "",
		},
		// New test cases for additional coverage
		{
			name: "Case Sensitive ApiKey Prefix",
			headers: http.Header{
				"Authorization": []string{"apikey test-key"},
			},
			wantAPIKey:     "",
			wantErr:        nil,
			wantErrMessage: "malformed authorization header",
		},
		{
			name: "Multiple Spaces in Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey    test-key"},
			},
			wantAPIKey:     "   test-key",
			wantErr:        nil,
			wantErrMessage: "",
		},
		{
			name: "Only ApiKey Prefix",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantAPIKey:     "",
			wantErr:        nil,
			wantErrMessage: "malformed authorization header",
		},
		{
			name: "Multiple Headers with Different Cases",
			headers: http.Header{
				"Authorization": []string{"ApiKey first-key"},
				"authorization": []string{"ApiKey second-key"},
			},
			wantAPIKey:     "first-key",
			wantErr:        nil,
			wantErrMessage: "",
		},
		{
			name: "Header with Newlines",
			headers: http.Header{
				"Authorization": []string{"ApiKey\nnewline-key"},
			},
			wantAPIKey:     "\nnewline-key",
			wantErr:        nil,
			wantErrMessage: "",
		},
		{
			name: "Header with Tabs",
			headers: http.Header{
				"Authorization": []string{"ApiKey\t\ttab-key"},
			},
			wantAPIKey:     "\t\ttab-key",
			wantErr:        nil,
			wantErrMessage: "",
		},
		{
			name: "Multiple Headers with Invalid Format",
			headers: http.Header{
				"Authorization": []string{"invalid", "ApiKey valid-key"},
			},
			wantAPIKey:     "",
			wantErr:        nil,
			wantErrMessage: "malformed authorization header",
		},
		{
			name: "Header with Unicode Characters",
			headers: http.Header{
				"Authorization": []string{"ApiKey 你好世界"},
			},
			wantAPIKey:     "你好世界",
			wantErr:        nil,
			wantErrMessage: "",
		},
		{
			name: "Header with Control Characters",
			headers: http.Header{
				"Authorization": []string{"ApiKey \x00\x01\x02\x03"},
			},
			wantAPIKey:     "\x00\x01\x02\x03",
			wantErr:        nil,
			wantErrMessage: "",
		},
		{
			name: "Header with Maximum Length",
			headers: http.Header{
				"Authorization": []string{"ApiKey " + string(make([]byte, 8192))},
			},
			wantAPIKey:     string(make([]byte, 8192)),
			wantErr:        nil,
			wantErrMessage: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)
			if err != nil {
				if tt.wantErr == nil {
					t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if err.Error() != tt.wantErrMessage {
					t.Errorf("GetAPIKey() error message = %v, wantErrMessage %v", err.Error(), tt.wantErrMessage)
					return
				}
			}
			if got != tt.wantAPIKey {
				t.Errorf("GetAPIKey() = %v, want %v", got, tt.wantAPIKey)
			}
		})
	}
}
