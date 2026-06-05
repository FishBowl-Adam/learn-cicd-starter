package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headerValue string
		wantKey     string
		wantErr     error
	}{
		{
			name:        "no authorization header",
			headerValue: "",
			wantKey:     "",
			wantErr:     ErrNoAuthHeaderIncluded,
		},
		{
			name:        "malformed header - missing key",
			headerValue: "ApiKey",
			wantKey:     "",
			wantErr:     errMalformed,
		},
		{
			name:        "malformed header - wrong scheme",
			headerValue: "Bearer sometoken",
			wantKey:     "",
			wantErr:     errMalformed,
		},
		{
			name:        "valid ApiKey header",
			headerValue: "ApiKey my-secret-key",
			wantKey:     "my-secret-key",
			wantErr:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.headerValue != "" {
				headers.Set("Authorization", tt.headerValue)
			}

			gotKey, gotErr := GetAPIKey(headers)

			if gotKey != tt.wantKey {
				t.Errorf("got key %q, want %q", gotKey, tt.wantKey)
			}

			if tt.wantErr == errMalformed {
				// any non-nil, non-ErrNoAuthHeaderIncluded error counts as malformed
				if gotErr == nil || gotErr == ErrNoAuthHeaderIncluded {
					t.Errorf("got err %v, want a malformed header error", gotErr)
				}
			} else if gotErr != tt.wantErr {
				t.Errorf("got err %v, want %v", gotErr, tt.wantErr)
			}
		})
	}
}

// sentinel used only in the test table to signal "any malformed error"
var errMalformed = errors.New("malformed")
