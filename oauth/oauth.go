// Package oauth provides authentication profile support for APIs that require
// OAuth 2.0 auth.
package oauth

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/rigetti/openapi-cli-generator/cli"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
	"gopkg.in/h2non/gentleman.v2/context"
)

type config struct {
	getParams func(profile map[string]string) url.Values
	extra     []string
	scopes    []string
}

// ErrInvalidProfile is thrown when a profile is missing or invalid.
var ErrInvalidProfile = errors.New("invalid profile")

// GetParams registers a function to get additional token endpoint parameters
// to include in the request when fetching a new token.
func GetParams(f func(profile map[string]string) url.Values) func(*config) error {
	return func(c *config) error {
		c.getParams = f
		return nil

	}
}

// Extra provides the names of additional parameters to use to store information
// in user profiles. Use `cli.GetActiveProfile.Info("default")["name"]` to access it.
func Extra(names ...string) func(*config) error {
	return func(c *config) error {
		c.extra = names
		return nil
	}
}

// Scopes sets a list of scopes to request for the token.
func Scopes(scopes ...string) func(*config) error {
	return func(c *config) error {
		c.scopes = scopes
		return nil
	}
}

// TokenMiddleware is a wrapper around TokenHandler.
func TokenMiddleware(source oauth2.TokenSource, ctx *context.Context, h context.Handler) {
	// Setup logger with the current profile.
	log := ctx.Get("log").(*zerolog.Logger).
		With().Str("profileName", cli.RunConfig.Settings.ProfileName).Logger()

	if err := TokenHandler(source, &log, ctx.Request); err != nil {
		h.Error(ctx, err)
		return
	}
}

func getOauth2Token(source oauth2.TokenSource, log *zerolog.Logger) (token *oauth2.Token, err error) {
	var cached *oauth2.Token

	credentials := cli.RunConfig.GetCredentials()
	expiry, err := credentials.TokenPayload.ExpiresAt()
	if err != nil {
		log.Debug().Err(err).Msg("failed to parse claims expiration")
		err = nil
		// if parsing the token failed, log the failure, but treat the token
		// as expired, so that we can refresh it below.
	}
	if !expiry.IsZero() {
		log.Debug().Msg("Loading token from cache.")
		cached = &oauth2.Token{
			AccessToken:  credentials.TokenPayload.AccessToken,
			RefreshToken: credentials.TokenPayload.RefreshToken,
			TokenType:    credentials.TokenPayload.TokenType,
			Expiry:       expiry,
		}
	}

	if cached != nil {
		// Wrap the token source preloaded with our cached token.
		source = oauth2.ReuseTokenSource(cached, source)
	}

	// Get the next available token from the source.
	token, err = source.Token()
	if err != nil {
		return
	}

	return
}

// TokenHandler takes a token source, gets a token, and modifies a request to
// add the token auth as a header. Uses the CLI cache to store tokens on a per-
// profile basis between runs.
func TokenHandler(source oauth2.TokenSource, log *zerolog.Logger, request *http.Request) error {
	token, err := getOauth2Token(source, log)
	if err != nil {
		return err
	}

	// Token either didn't exist in the cache or has changed, so let's write
	// the new values to the CLI cache.
	log.Debug().Msg("Token refreshed. Updating cache.")

	err = cli.RunConfig.UpdateCredentialsToken(cli.RunConfig.GetProfile().CredentialsName, token)
	if err != nil {
		return err
	}

	// Set the auth header so the request can be made.
	token.SetAuthHeader(request)
	return nil
}
