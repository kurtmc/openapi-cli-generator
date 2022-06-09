package cli

import (
	"fmt"
	"golang.org/x/oauth2"
	"gopkg.in/h2non/gentleman.v2/context"
	"net/http"
	"os"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// AuthHandler describes a handler that can be called on a request to inject
// auth information and is agnostic to the type of auth.
type AuthHandler interface {
	ExecuteFlow(log *zerolog.Logger) (*oauth2.Token, error)

	// ProfileKeys returns the key names for fields to store in the profileName.
	ProfileKeys() []string

	// OnRequest gets run before the request goes out on the wire.
	OnRequest(log *zerolog.Logger, request *http.Request) error
}

type OAuthHandler interface {
	NewToken() (token *oauth2.Token, err error)
}

// AuthHandlers is the map of registered auth type names to handlers
var AuthHandlers = make(map[string]AuthHandler)

var authInitialized bool

// BuildSecretsCommands sets up basic commands and the credentials file so that new auth
// handlers can be registered. This MUST be called only after auth handlers have
// been set up through UseAuth.
func BuildSecretsCommands() (cmd *cobra.Command) {
	// Add base auth commands
	cmd = &cobra.Command{
		Use:   "secrets",
		Short: "Interact with your secrets.toml file",
	}

	cmd.AddCommand(
		buildSecretsAddCredentialsCommand(),
		buildSecretsListCredentialsCommand(),
		buildSecretsGetCommand(),
		buildSecretsSetCommand(),
		buildSecretsRefreshCredentialsCommand(),
		buildSecretsRemoveCredentialsCommand(),
		buildSecretsPrintClaimsCommand())

	return
}

func buildSecretsAddCredentialsCommand() (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:   "add-credentials <credentials-name> <auth-server-name>",
		Short: "Add a new set of credentials",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			credentialName := strings.Replace(args[0], ".", "-", -1)
			authServerName := strings.Replace(args[1], ".", "-", -1)
			logger := log.With().Str("credentials-name", credentialName).Logger()
			_, exists := RunConfig.Secrets.Credentials[credentialName]
			if exists {
				logger.Fatal().Msgf("credential %q already exists", credentialName)
			}

			handler, ok := AuthHandlers[authServerName]
			if !ok {
				logger.Fatal().Msgf("auth server %q oauth2 flow has not been set up", authServerName)
			}
			oauthHandler, ok := handler.(OAuthHandler)
			if !ok {
				logger.Fatal().Msgf("auth server %q does not support an OAuth2 flow", authServerName)
			}

			token, err := oauthHandler.NewToken()
			if err != nil {
				logger.Fatal().Err(err).Msg("error while authenticating")
			}

			err = RunConfig.UpdateCredentialsToken(credentialName, token)
			if err != nil {
				logger.Fatal().Err(err).Msg("an error occurred writing credentials to file")
			}
		},
	}
	return
}

func buildSecretsRemoveCredentialsCommand() (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:   "remove-credentials <credentials-name>",
		Short: "Remove credentials. This does not remove any related profiles.",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			credentialsName := strings.Replace(args[0], ".", "-", -1)
			logger := log.With().Str("credentials-name", credentialsName).Logger()

			err := RunConfig.delete(RunConfig.secretsPath, map[string]string{"credentials": credentialsName})
			if err != nil {
				logger.Fatal().Err(err).Msg("Failed to write updated settings")
			}
		},
	}
	return
}

func buildSecretsListCredentialsCommand() (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:   "list-credentials",
		Short: "List available credentials",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			credentials := RunConfig.Secrets.Credentials
			if credentials != nil {
				table := tablewriter.NewWriter(os.Stdout)
				table.SetHeader([]string{"Name", "Client ID", "Issuer"})

				for credentialName, credential := range credentials {
					claims, err := credential.TokenPayload.ParseClaimsUnverified()
					var cid string
					var iss string
					if err != nil {
						log.Debug().Err(err).Msgf("failed to parse credentials %q", credentialName)
					} else {
						iss, _ = claims["iss"].(string)
						cid, _ = claims["cid"].(string)
					}
					table.Append([]string{credentialName, cid, iss})
				}
				table.Render()
			} else {
				log.Info().Msgf("No credentials configured. Use `%s auth add-credentials` to add one.\n", Root.CommandPath())
			}
		},
	}
	return
}

func buildSecretsRefreshCredentialsCommand() (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:   "refresh-credentials <profile-name>",
		Short: "Refresh credentials associated with specified profile",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			profileName := strings.Replace(args[0], ".", "-", -1)
			logger := log.With().Str("profile", profileName).Logger()
			profile, exists := RunConfig.Settings.Profiles[profileName]
			if !exists {
				logger.Fatal().Msgf("profile %q does not exist", profileName)
			}

			_, exists = RunConfig.Secrets.Credentials[profile.CredentialsName]
			if !exists {
				logger.Fatal().Msgf("credential %q does not exist", profile.CredentialsName)
			}

			handler, ok := AuthHandlers[profile.AuthServerName]
			if !ok {
				logger.Fatal().Msgf("auth server %q oauth2 flow has not been set up", profile.AuthServerName)
			}
			token, err := handler.ExecuteFlow(&logger)
			if err != nil {
				logger.Fatal().Err(err).Msg("error while authenticating")
			}
			err = RunConfig.UpdateCredentialsToken(profile.CredentialsName, token)
			if err != nil {
				logger.Fatal().Err(err).Msg("an error occurred writing credentials to file")
			}
		},
	}
	return
}

func buildSecretsPrintClaimsCommand() (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:   "print-claims <credentials-name>",
		Short: "Print claims of the specified credentials",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			credentialsName := strings.Replace(args[0], ".", "-", -1)
			logger := log.With().Str("credentials-name", credentialsName).Logger()

			credentials, exists := RunConfig.Secrets.Credentials[credentialsName]
			if !exists {
				logger.Fatal().Msgf("credential %q does not exist", credentialsName)
			}

			claims, err := credentials.TokenPayload.ParseClaimsUnverified()
			if err != nil {
				logger.Fatal().Err(err).Msg("failed to parse claims")
			}

			if err = Formatter.Format(claims); err != nil {
				log.Fatal().Err(err).Msg("Formatting failed")
			}
		},
	}
	return
}

func buildSecretsGetCommand() (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:   "get <secrets-path>",
		Short: "Get a value from secrets.toml using a \".\" separated path.",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			runConfig(RunConfig.secretsPath, RunConfig.Secrets, args)
		},
	}
	return
}

func buildSecretsSetCommand() (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:   "set <secrets-path> <value>",
		Short: "Set a value in secrets.toml using a \".\" separated path.",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			runConfig(RunConfig.secretsPath, RunConfig.Secrets, args)
		},
	}
	return
}

// UseAuth registers a new auth handler for a given type name. For backward-
// compatibility, the auth type name can be a blank string. It is recommended
// to always pass a value for the type name.
func UseAuth(typeName string, handler AuthHandler) {
	if !authInitialized {
		// Install auth middleware
		Client.UseRequest(func(ctx *context.Context, h context.Handler) {
			handler := AuthHandlers[RunConfig.GetProfile().AuthServerName]
			if handler == nil {
				h.Error(ctx, fmt.Errorf("no handler for auth server %q", RunConfig.GetProfile().AuthServerName))
				return
			}

			if err := handler.OnRequest(ctx.Get("log").(*zerolog.Logger), ctx.Request); err != nil {
				h.Error(ctx, err)
				return
			}

			h.Next(ctx)
		})
		authInitialized = true
	}

	// Register the handler by its type.
	AuthHandlers[typeName] = handler
}
