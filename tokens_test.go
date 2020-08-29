package awstokens_test

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/dgrijalva/jwt-go"
	"github.com/mec07/awstokens"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

type mockAuthInitiator struct {
	shouldError bool
}

const (
	refreshedAccessToken = "refreshed_access_token"
	refreshedIDToken     = "refreshed_id_token"
)

func (m *mockAuthInitiator) InitiateAuth(input *cognitoidentityprovider.InitiateAuthInput) (*cognitoidentityprovider.InitiateAuthOutput, error) {
	if m.shouldError {
		return nil, errors.New("InitiateAuth failed")
	}

	result := cognitoidentityprovider.AuthenticationResultType{
		AccessToken: aws.String(refreshedAccessToken),
		IdToken:     aws.String(refreshedIDToken),
	}
	output := cognitoidentityprovider.InitiateAuthOutput{
		AuthenticationResult: &result,
	}
	return &output, nil
}

func TestNewAuth(t *testing.T) {
	_, err := awstokens.NewAuth(awstokens.Config{})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAuth(t *testing.T) {
	signingKey := []byte("random key")

	validToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Hour).UTC().Unix(),
	}).SignedString(signingKey)
	if err != nil {
		t.Fatalf("jwt.Token.SigningMethodHS256: %v", err)
	}

	expiredToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		ExpiresAt: time.Now().Add(-time.Hour).UTC().Unix(),
	}).SignedString(signingKey)
	if err != nil {
		t.Fatalf("jwt.Token.SigningMethodHS256: %v", err)
	}
	_ = expiredToken

	table := []struct {
		name              string
		idToken           string
		accessToken       string
		refreshToken      string
		expectedAuthToken string
		shouldUseIDToken  bool
		shouldError       bool
	}{
		{
			name:              "Auth token is inputted access token",
			idToken:           "id_token",
			accessToken:       validToken,
			refreshToken:      "refresh_token",
			expectedAuthToken: validToken,
		},
		{
			name:              "Auth token is inputted ID token",
			idToken:           validToken,
			accessToken:       "access_token",
			refreshToken:      "refresh_token",
			expectedAuthToken: validToken,
			shouldUseIDToken:  true,
		},
		{
			name:              "Auth token is refreshed access token",
			idToken:           "id_token",
			accessToken:       expiredToken,
			refreshToken:      "refresh_token",
			expectedAuthToken: refreshedAccessToken,
		},
		{
			name:              "Auth token is refreshed ID token",
			idToken:           expiredToken,
			accessToken:       "access_token",
			refreshToken:      "refresh_token",
			expectedAuthToken: refreshedIDToken,
			shouldUseIDToken:  true,
		},
		{
			name:              "refresh failure",
			idToken:           "id_token",
			accessToken:       expiredToken,
			refreshToken:      "refresh_token",
			expectedAuthToken: refreshedIDToken,
			shouldError:       true,
		},
	}

	for _, test := range table {
		test := test
		t.Run(test.name, func(t *testing.T) {
			config := awstokens.Config{
				IDToken:          test.idToken,
				AccessToken:      test.accessToken,
				RefreshToken:     test.refreshToken,
				ClientID:         "1234",
				Region:           "eu-west-2",
				ShouldUseIDToken: test.shouldUseIDToken,
			}
			authInitiator := &mockAuthInitiator{shouldError: test.shouldError}
			auth := awstokens.NewAuthWithAuthInitiator(authInitiator, config)

			authToken, err := auth.GetAuthToken()
			if test.shouldError {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("awstokens.Auth.GetAuthToken: %v", err)
			}

			assert.Equal(t, test.expectedAuthToken, authToken)
		})
	}
}
