package awstokens

import (
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

const defaultExpiryMargin time.Duration = 5 * time.Second

// AuthInitiator is an interface that represents the cognitoidentityprovider
// library client, which allows you to refresh tokens.
type AuthInitiator interface {
	InitiateAuth(input *cognitoidentityprovider.InitiateAuthInput) (*cognitoidentityprovider.InitiateAuthOutput, error)
}

// Config contains the initial settings for the Auth.
type Config struct {
	// Actual tokens
	AccessToken, IDToken, RefreshToken string
	// Info required to refresh the tokens
	ClientID, Region string
	// By default use the access token for auth, but if this is true then use ID
	// token instead
	ShouldUseIDToken bool
	// ExpiryMargin is the margin in which a token is considered to be expired.
	// If it is left empty (i.e. 0) then we will use the default value of 5
	// seconds.
	ExpiryMargin time.Duration
}

// Auth contains the AWS tokens and some extra info for refreshing them.
type Auth struct {
	mu            sync.RWMutex
	authInitiator AuthInitiator
	// Actual tokens
	accessToken, idToken, refreshToken string
	// Info required to refresh the tokens
	clientID string
	// Extra settings
	useIDToken   bool
	expiryMargin time.Duration
}

// NewAuth returns a pointer to an Auth using the provided Config.
func NewAuth(config Config) (*Auth, error) {
	// Put in fake creds because we need to provide some creds or else
	// NewSession will return an error. We don't need valid creds to refresh
	// tokens.
	creds := credentials.NewStaticCredentials("access_id", "access_secret_key", "")
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(config.Region),
		Credentials: creds,
	})
	if err != nil {
		return nil, errors.Wrap(err, "session.NewSession")
	}
	cognitoIDP := cognitoidentityprovider.New(sess)

	return NewAuthWithAuthInitiator(cognitoIDP, config), nil
}

// NewAuthWithAuthInitiator returns a pointer to an Auth using the provided config and AuthInitiator.
func NewAuthWithAuthInitiator(authInitiator AuthInitiator, config Config) *Auth {
	expiryMargin := defaultExpiryMargin
	if config.ExpiryMargin > 0 {
		expiryMargin = config.ExpiryMargin
	}

	return &Auth{
		authInitiator: authInitiator,
		accessToken:   config.AccessToken,
		idToken:       config.IDToken,
		refreshToken:  config.RefreshToken,
		clientID:      config.ClientID,
		useIDToken:    config.ShouldUseIDToken,
		expiryMargin:  expiryMargin,
	}
}

// GetAuthToken returns the Access token by default, but if ShouldUseIDToken has
// been set to true it returns the ID token. If the token it is going to return
// has expired then it attempts to refresh the token before returning it.
func (t *Auth) GetAuthToken() (string, error) {
	token := t.getAuthToken()
	if !tokenIsExpired(token, t.getExpiryMargin()) {
		return token, nil
	}

	if err := t.refreshTokens(); err != nil {
		return "", errors.Wrap(err, "refresh failed")
	}
	return t.getAuthToken(), nil
}

func (t *Auth) getAuthToken() string {
	if t.shouldUseIDToken() {
		return t.getIDToken()
	}
	return t.getAccessToken()
}

func (t *Auth) getIDToken() string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.idToken
}

func (t *Auth) getAccessToken() string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.accessToken
}

func (t *Auth) shouldUseIDToken() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.useIDToken
}

func (t *Auth) getExpiryMargin() time.Duration {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.expiryMargin
}

func (t *Auth) getRefreshToken() string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.refreshToken
}

func (t *Auth) getClientID() string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.clientID
}

func (t *Auth) setIDToken(token string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.idToken = token
}

func (t *Auth) setAccessToken(token string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.accessToken = token
}

func (t *Auth) refreshTokens() error {
	res, err := t.authInitiator.InitiateAuth(&cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: aws.String(cognitoidentityprovider.AuthFlowTypeRefreshTokenAuth),
		AuthParameters: map[string]*string{
			cognitoidentityprovider.AuthFlowTypeRefreshToken: aws.String(t.getRefreshToken()),
		},
		ClientId: aws.String(t.getClientID()),
	})
	if err != nil {
		return errors.Wrap(err, "cognitoidentityprovider.New.InitiateAuth")
	}

	if res.AuthenticationResult == nil {
		return errors.New("cognitoidentityprovider.New.InitiateAuth response has no AuthenticationResult")
	}
	if res.AuthenticationResult.AccessToken == nil {
		return errors.New("cognitoidentityprovider.New.InitiateAuth response has no AccessToken")
	}
	if res.AuthenticationResult.IdToken == nil {
		return errors.New("cognitoidentityprovider.New.InitiateAuth response has no IdToken")
	}
	t.setAccessToken(*res.AuthenticationResult.AccessToken)
	t.setIDToken(*res.AuthenticationResult.IdToken)

	return nil
}

// tokenIsExpired checks if the provided token has expired, or is shortly due
// to expire.
func tokenIsExpired(token string, expiryMargin time.Duration) bool {
	adjustedExpiryTime := getTokenExpiryTime(token) - int64(expiryMargin/time.Second)
	return time.Now().UTC().Unix() > adjustedExpiryTime
}

func getTokenExpiryTime(token string) int64 {
	// Parse the token without validating it.
	claims := jwt.StandardClaims{}
	_, _ = jwt.ParseWithClaims(token, &claims, nil)
	return claims.ExpiresAt
}
