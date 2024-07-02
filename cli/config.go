package cli

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/olekukonko/tablewriter"
	"github.com/kurtmc/openapi-cli-generator/cli/internal/util"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cast"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"gopkg.in/h2non/gentleman.v2"
	"os"
	"reflect"
	"strings"
	"time"
)

type TokenPayload struct {
	ExpiresIn    int    `mapstructure:"expires_in"`
	RefreshToken string `mapstructure:"refresh_token"`
	AccessToken  string `mapstructure:"access_token"`
	IDToken      string `mapstructure:"id_token"`
	Scope        string `mapstructure:"scope"`
	TokenType    string `mapstructure:"token_type"`
}

func (tp TokenPayload) ToMap() map[string]interface{} {
	m := make(map[string]interface{})
	m["expires_in"] = tp.ExpiresIn
	m["refresh_token"] = tp.RefreshToken
	m["access_token"] = tp.AccessToken
	m["expires_in"] = tp.ExpiresIn
	m["id_token"] = tp.IDToken
	m["scope"] = tp.Scope
	m["token_type"] = tp.TokenType
	return m
}

func (tp TokenPayload) ParseClaimsUnverified() (jwt.MapClaims, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tp.AccessToken, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, nil
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed to parse claims, found %T", token.Claims)
	}

	return claims, nil
}

func (tp TokenPayload) ExpiresAt() (time.Time, error) {
	claims, err := tp.ParseClaimsUnverified()
	if err != nil {
		return time.Time{}, err
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		err := fmt.Errorf("expected float64 for exp claim, received %q", reflect.TypeOf(claims["exp"]))
		return time.Time{}, err
	}
	return time.Unix(int64(exp), 0), nil
}

type Credentials struct {
	TokenPayload TokenPayload `mapstructure:"token_payload"`
}

type Secrets struct {
	Credentials map[string]Credentials `mapstructure:"credentials"`
}

type VerbosityType string

const VerbosityTypePanic VerbosityType = "panic"
const VerbosityTypeFatal VerbosityType = "fatal"
const VerbosityTypeError VerbosityType = "error"
const VerbosityTypeWarn VerbosityType = "warn"
const VerbosityTypeInfo VerbosityType = "info"
const VerbosityTypeDebug VerbosityType = "debug"

type CLI struct {
	Verbosity    VerbosityType `mapstructure:"verbosity"`
	OutputFormat string        `mapstructure:"output_format"`
	Query        string        `mapstructure:"query"`
	Raw          bool          `mapstructure:"raw"`
}

func (c CLI) ZeroLogLevel() zerolog.Level {
	switch c.Verbosity {
	case VerbosityTypePanic:
		return zerolog.PanicLevel
	case VerbosityTypeFatal:
		return zerolog.FatalLevel
	case VerbosityTypeError:
		return zerolog.ErrorLevel
	case VerbosityTypeWarn:
		return zerolog.WarnLevel
	case VerbosityTypeInfo:
		return zerolog.InfoLevel
	case VerbosityTypeDebug:
		return zerolog.DebugLevel
	default:
		return zerolog.WarnLevel
	}
}

type AuthServer struct {
	ClientID string   `mapstructure:"client_id"`
	Issuer   string   `mapstructure:"issuer"`
	Keys     []string `mapstructure:"keys"`
	ListKeys []string `mapstructure:"list_keys"`
	Scopes []string `mapstructure:"scopes"`
}

type Applications struct {
	CLI CLI `mapstructure:"cli"`
}

type Profile struct {
	ApiURL          string `mapstructure:"api_url"`
	AuthServerName  string `mapstructure:"auth_server_name"`
	CredentialsName string `mapstructure:"credentials_name"`
	Headers				[]string `mapstructure:"headers"`
	Extra           map[string]interface{} `mapstructure:",remain"`
	Applications `mapstructure:"applications"`
}

// ToProfileViperKeys returns a map of Viper keys to values for this profile. It includes
// the top-level profile.{profileName} prefix, which is what Viper will use when
// (un)marshalling Settings. Note, this includes embedding all of the key value pairs
// in Profile.Extra. It does not include any field that is set to its default value.
// Why is this needed? First, mapstructure.Decode will inaccurately nest key value
// pairs in Profile.Extra under an "Extra" key. Second, viper.WriteConfig
// will return the following error on custom string fields, such as VerbosityType, during
// TOML marshalling:
// While marshaling config: cannot convert type cli.VerbosityType to Tree
// To side step these issues, we provide this as a convenience method for representing
// a profile as a map of Viper keys and values. Clients can then pass the returned map
// to ClientConfiguration.WriteSettings.
func (p Profile) ToProfileViperKeys(profileName, apiURL string) map[string]interface{} {
	defaults := NewGlobalFlagDefaults("")

	viperKeys := make(map[string]interface{})

	if p.ApiURL != defaults.ApiURL {
		viperKeys[fmt.Sprintf("profiles.%s.api_url", profileName)] = p.ApiURL
	}
	if p.CredentialsName != defaults.CredentialsName {
		viperKeys[fmt.Sprintf("profiles.%s.credentials_name", profileName)] = p.CredentialsName
	}
	if p.AuthServerName != defaults.AuthServerName {
		viperKeys[fmt.Sprintf("profiles.%s.auth_server_name", profileName)] = p.AuthServerName
	}
	if len(p.Headers) != 0 {
		viperKeys[fmt.Sprintf("profiles.%s.headers", profileName)] = p.Headers
	}
	if p.Applications.CLI.Raw != defaults.Raw {
		viperKeys[fmt.Sprintf("profiles.%s.raw", profileName)] = p.Applications.CLI.Raw
	}
	if p.Applications.CLI.OutputFormat != "" && p.Applications.CLI.OutputFormat != defaults.OutputFormat {
		viperKeys[fmt.Sprintf("profiles.%s.output_format", profileName)] = p.Applications.CLI.OutputFormat
	}
	if p.Applications.CLI.Verbosity != "" && p.Applications.CLI.Verbosity != VerbosityType(defaults.Verbosity) {
		viperKeys[fmt.Sprintf("profiles.%s.verbosity", profileName)] = string(p.Applications.CLI.Verbosity)
	}
	for key, value := range p.Extra {
		viperKeys[fmt.Sprintf("profiles.%s.%s", profileName, key)] = value
	}
	return viperKeys
}

type Settings struct {
	// ProfileName will be read from settings.toml default_profile_name,
	// then the %envPrefix%_PROFILE_NAME, and then the --profile-name global flag.
	ProfileName string                `mapstructure:"default_profile_name"`
	Profiles           map[string]Profile    `mapstructure:"profiles"`
	AuthServers        map[string]AuthServer `mapstructure:"auth_servers"`
	viper              *viper.Viper
}

type ClientConfiguration struct {
	Secrets      Secrets  `mapstructure:"secrets"`
	Settings     Settings `mapstructure:"settings"`
	secretsPath  string
	settingsPath string
	globalFlags []GlobalFlag
}

func (cc ClientConfiguration) GetProfile() Profile {
	return cc.Settings.Profiles[cc.Settings.ProfileName]
}

func (cc ClientConfiguration) GetAuthServer() AuthServer {
	return cc.Settings.AuthServers[cc.GetProfile().AuthServerName]
}

func (cc ClientConfiguration) GetCredentials() Credentials {
	return cc.Secrets.Credentials[cc.GetProfile().CredentialsName]
}

func (cc *ClientConfiguration) bindGlobalFlags(envPrefix string) (err error) {
	for _, globalFlag := range cc.globalFlags {
		err = globalFlag.bindFlag(cc.Settings.viper, envPrefix, cc.Settings)
		if err != nil {
			return
		}
	}

	var settings Settings
	err = cc.Settings.viper.Unmarshal(&settings)
	if err != nil {
		return
	}
	cc.Settings = settings
	return
}

func loadSecrets(secretsFilePath string) (secrets Secrets, err error) {
	touchFile(secretsFilePath)

	v := viper.New()

	v.SetConfigFile(secretsFilePath)
	err = v.ReadInConfig()
	if err != nil {
		return
	}

	err = v.Unmarshal(&secrets)
	if err != nil {
		return
	}

	if secrets.Credentials == nil {
		secrets.Credentials = make(map[string]Credentials)
	}

	return secrets, nil
}

func loadSettings(settingsFilePath string) (settings Settings, err error) {
	touchFile(settingsFilePath)

	v := viper.New()

	v.SetConfigFile(settingsFilePath)
	err = v.ReadInConfig()
	if err != nil {
		return
	}

	err = v.Unmarshal(&settings)
	if err != nil {
		return
	}

	if settings.AuthServers == nil {
		settings.AuthServers = make(map[string]AuthServer)
	}
	if settings.Profiles == nil {
		settings.Profiles = make(map[string]Profile)
	}
	settings.viper = v
	return settings, nil
}

func touchFile(fileName string) error {
	_, err := os.Stat(fileName)
	if os.IsNotExist(err) {
		file, err := os.Create(fileName)
		if err != nil {
			return err
		}
		defer file.Close()
	}
	return nil
}

func InitConfiguration(envPrefix, settingsFilePath, secretsFilePath string, globalFlags []GlobalFlag) (err error) {
	clientConfiguration, err := LoadConfiguration(envPrefix, settingsFilePath, secretsFilePath, globalFlags)
	if err != nil {
		return
	}
	zerolog.SetGlobalLevel(clientConfiguration.GetProfile().CLI.ZeroLogLevel())
	RunConfig = clientConfiguration
	return
}

// LoadConfiguration loads secret and settings files. It will additional override those persisted values
// with (1) environment variables and (2) flag values (in order of increasing precedence).
func LoadConfiguration(envPrefix, settingsFilePath, secretsFilePath string, globalFlags []GlobalFlag) (config ClientConfiguration, err error) {
	secrets, err := loadSecrets(secretsFilePath)
	if err != nil {
		return
	}

	settings, err := loadSettings(settingsFilePath)
	if err != nil {
		return
	}

	config = ClientConfiguration{
		Secrets:     secrets,
		secretsPath: secretsFilePath,
		Settings:    settings,
		settingsPath: settingsFilePath,
		globalFlags: globalFlags,
	}

	err = config.bindGlobalFlags(envPrefix)
	if err != nil {
		return
	}

	RegisterBeforeAll(MakeAddHeaders(config))

	return
}

func MakeAddHeaders(config ClientConfiguration) BeforeHandlerFunc {
	return func(s string, v *viper.Viper, request *gentleman.Request) {
		logger := log.With().Str("profile", RunConfig.Settings.ProfileName).Logger()
		for _, header := range config.GetProfile().Headers {
			parts := strings.SplitN(header, ": ", 1)
			if len(parts) != 2 {
				logger.Warn().Err(fmt.Errorf("could not parse header %q", header))
				continue
			}
			logger.Debug().Msgf("adding header %s: %s", parts[0], strings.Repeat("*", len(parts[1])))
			request.AddHeader(parts[0], parts[1])
		}
	}
}

func (cc *ClientConfiguration) UpdateCredentialsToken(credentialsName string, token *oauth2.Token) error {
	tokenPayload := cc.Secrets.Credentials[credentialsName].TokenPayload
	tokenPayload.AccessToken = token.AccessToken
	tokenPayload.TokenType = token.TokenType
	if token.RefreshToken != "" {
		tokenPayload.RefreshToken = token.RefreshToken
	}
	credentials := cc.Secrets.Credentials[credentialsName]
	credentials.TokenPayload = tokenPayload
	cc.Secrets.Credentials[credentialsName] = credentials

	updates := make(map[string]interface{})
	updates[fmt.Sprintf("credentials.%s.token_payload.access_token", credentialsName)] = tokenPayload.AccessToken
	updates[fmt.Sprintf("credentials.%s.token_payload.refresh_token", credentialsName)] = tokenPayload.RefreshToken
	updates[fmt.Sprintf("credentials.%s.token_payload.id_token", credentialsName)] = tokenPayload.IDToken
	updates[fmt.Sprintf("credentials.%s.token_payload.token_type", credentialsName)] = tokenPayload.TokenType

	return cc.WriteSecrets(updates)
}

func (cc ClientConfiguration) WriteSettings(updates map[string]interface{}) (err error) {
	return cc.write(cc.settingsPath, updates)
}

func (cc ClientConfiguration) WriteSecrets(updates map[string]interface{}) (err error) {
	return cc.write(cc.secretsPath, updates)
}

func (cc ClientConfiguration) write(filePath string, updates map[string]interface{}) (err error) {
	v := viper.New()

	v.SetConfigFile(filePath)
	err = v.ReadInConfig()
	if err != nil {
		return err
	}

	for path, value := range updates {
		v.Set(path, value)
	}

	remove, restore, err := util.BackupFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to backup %q before writing update: %+v", filePath, err)
	}

	err = v.WriteConfig()

	if err != nil {
		restoreErr := restore()
		if restoreErr != nil {
			err = fmt.Errorf("failed to restore %q after %+v: %+v", filePath, err, restoreErr)
		}
		return err
	}
	return remove()
}

func (cc ClientConfiguration) delete(filePath string, paths map[string]string) (err error) {
	v := viper.New()

	v.SetConfigFile(filePath)
	err = v.ReadInConfig()
	if err != nil {
		return
	}

	for parent, child := range paths {
		delete(v.Get(parent).(map[string]interface{}), child)
	}

	remove, restore, err := util.BackupFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to backup %q before writing update: %+v", filePath, err)
	}

	err = v.WriteConfig()

	if err != nil {
		restoreErr := restore()
		if restoreErr != nil {
			err = fmt.Errorf("failed to restore %q after %+v: %+v", filePath, err, restoreErr)
		}
		return err
	}
	return remove()
}

func BuildSettingsCommands() (configCommand *cobra.Command) {
	configCommand = &cobra.Command{
		Use:   "settings",
		Short: "Interact with your settings.toml file",
	}
	configCommand.AddCommand(
		buildSettingsAddAuthServerCommand(),
		buildSettingsListAuthServersCommand(),
		buildSettingsGetCommand(),
		buildSettingsSetCommand(),
		buildSettingsAddProfileCommand(),
		buildSettingsListProfilesCommand(),
		buildSettingsRemoveAuthServerCommand(),
		buildSettingsRemoveProfileCommand())

	return
}

func buildSettingsAddProfileCommand() (cmd *cobra.Command) {
	var apiURL string
	var authServerName string
	var credentialsName string
	var headers []string
	var extras []string

	cmd = &cobra.Command{
		Use:   "add-profile <profile-name>",
		Short: "Add a new profile. This will initialize or update the specified credentials as well.",
		Args:  cobra.ExactArgs(1),
		Run:  func(cmd *cobra.Command, args []string) {
			profileName := strings.Replace(args[0], ".", "-", -1)
			logger := log.With().Str("profile", profileName).Logger()

			err := cmd.MarkFlagRequired("credentials-name")
			if err != nil {
				logger.Fatal().Err(err).Msg("must specify credentials-name")
			}
			err = cmd.MarkFlagRequired("auth-server-name")
			if err != nil {
				logger.Fatal().Err(err).Msg("must specify auth-server-name")
			}
			err = cmd.MarkFlagRequired("api-url")
			if err != nil {
				logger.Fatal().Err(err).Msg("must specify api-url")
			}

			for _, header := range headers {
				parts := strings.Split(header, ": ")
				if len(parts) != 2 {
					logger.Fatal().Msgf("%q is not in %q format", header, "Header: value")
				}
			}

			extraMap := make(map[string]interface{})
			for _, extra := range extras {

				parts := strings.Split(extra, ": ")
				if len(parts) != 2 {
					logger.Fatal().Msgf("%q is not in %q format", extra, "key: value")
				}
				extraMap[parts[0]] = parts[1]
			}

			_, exists := RunConfig.Settings.Profiles[profileName]
			if exists {
				logger.Fatal().Msgf("profile %q already exists; try running remove-profile command first", profileName)
			}

			_, exists = RunConfig.Settings.AuthServers[authServerName]
			if !exists {
				logger.Fatal().Msgf("auth server %q does not exist; try running add-auth-server command first", authServerName)
			}

			handler, ok := AuthHandlers[authServerName]
			if !ok {
				logger.Fatal().Msgf("auth server %q oauth2 flow has not been set up", authServerName)
			}

			token, err := handler.ExecuteFlow(&logger)
			if err != nil {
				logger.Fatal().Err(err).Msg("error while authenticating")
			}
			err = RunConfig.UpdateCredentialsToken(credentialsName, token)
			if err != nil {
				logger.Fatal().Err(err).Msg("an error occurred writing credentials to file")
			}

			profile := Profile{
				ApiURL:          apiURL,
				AuthServerName:  authServerName,
				CredentialsName: credentialsName,
				Headers:         headers,
				Extra:           extraMap,
				Applications:    Applications{},
			}

			err = RunConfig.write(RunConfig.settingsPath, profile.ToProfileViperKeys(profileName, ""))
			if err != nil {
				logger.Fatal().Err(err).Msg("Failed to write updated settings")
			}
		},
	}
	cmd.Flags().StringVar(&apiURL, "api-url", "", "API base URL for all requests made with profile")
	cmd.Flags().StringVar(&authServerName, "auth-server-name", "", "auth server name against which to authenticate")
	cmd.Flags().StringVar(&credentialsName, "credentials-name", "", "credentials to authenticate requests")
	cmd.Flags().StringSliceVar(
		&headers,
		"headers",
		nil,
		"headers to add to all requests provided in \"Header: value\" format")
	cmd.Flags().StringSliceVar(
		&extras,
		"extras",
		nil,
		"extra fields provided in \"key: value\" format")

	return
}

func buildSettingsRemoveProfileCommand() (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:   "remove-profile <profile-name>",
		Short: "Remove a profile. This does not remove the related auth server or credentials.",
		Args:  cobra.ExactArgs(1),
		Run:  func(cmd *cobra.Command, args []string) {
			profileName := strings.Replace(args[0], ".", "-", -1)
			logger := log.With().Str("profile", profileName).Logger()

			err := RunConfig.delete(RunConfig.settingsPath, map[string]string{
				"profiles": profileName,
			})
			if err != nil {
				logger.Fatal().Err(err).Msg("Failed to remove profile")
			}
		},
	}
	return
}

func buildSettingsListProfilesCommand() (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:     "list-profiles",
		Short:   "List configured profiles",
		Args:    cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			profiles := RunConfig.Settings.Profiles
			if profiles != nil {
				table := tablewriter.NewWriter(os.Stdout)
				table.SetHeader([]string{"Name", "Auth server", "Credentials", "API URL", "Headers", "Extras"})

				// For each type name, draw a table with the relevant profileName keys
				for profileName, profile := range profiles {
					extras := make([]string, 0)
					for key, value := range profile.Extra {
						extras = append(extras, fmt.Sprintf("%s=%v", key, value))
					}
					table.Append([]string{
						profileName,
						profile.AuthServerName,
						profile.CredentialsName,
						profile.ApiURL,
						strings.Join(profile.Headers, ", "),
						strings.Join(extras, ", "),
					})
				}
				table.Render()
			} else {
				fmt.Printf("No profiles configured. Use `%s settings add-profile` to add one.\n", Root.CommandPath())
			}
		},
	}
	return
}

func buildSettingsAddAuthServerCommand() (cmd *cobra.Command) {
	var clientID string
	var issuer string
	cmd = &cobra.Command{
		Use:   "add-auth-server <auth-server-name>",
		Short: "Add a new authentication server",
		Args:  cobra.ExactArgs(1),
		Run:  func(cmd *cobra.Command, args []string) {
			logger := log.With().Str("profile", RunConfig.Settings.ProfileName).Logger()

			authServerName := strings.Replace(args[0], ".", "-", -1)
			_, exists := RunConfig.Settings.AuthServers[authServerName]
			if exists {
				logger.Fatal().Msgf("auth server %q already exists", authServerName)
			}

			err := cmd.MarkFlagRequired("client-id")
			if err != nil {
				logger.Fatal().Err(err).Msg("must specify client-id")
			}
			err = cmd.MarkFlagRequired("issuer")
			if err != nil {
				logger.Fatal().Err(err).Msg("must specify issuer")
			}

			updates := make(map[string]interface{})
			updates[fmt.Sprintf("auth_servers.%s.issuer", authServerName)] = issuer
			updates[fmt.Sprintf("auth_servers.%s.client_id", authServerName)] = clientID
			err = RunConfig.write(RunConfig.settingsPath, updates)
			if err != nil {
				logger.Fatal().Err(err).Msg("Failed to write updated settings")
			}
		},
	}
	cmd.Flags().StringVar(&clientID, "client-id", "", "The client id on behalf of which to issue OAuth2 requests.")
	cmd.Flags().StringVar(&issuer, "issuer", "", "The issuer, or authorization url, of the credential.")

	return
}

func buildSettingsRemoveAuthServerCommand() (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:   "remove-auth-server <auth-server-name>",
		Short: "Remove auth-server. This does not remove any related profiles.",
		Args:  cobra.ExactArgs(1),
		Run:  func(cmd *cobra.Command, args []string) {
			authServerName := strings.Replace(args[0], ".", "-", -1)
			logger := log.With().Str("auth server", authServerName).Logger()

			err := RunConfig.delete(RunConfig.settingsPath, map[string]string{"auth_servers": authServerName})
			if err != nil {
				logger.Fatal().Err(err).Msg("Failed to remove auth server")
			}
		},
	}
	return
}

func buildSettingsListAuthServersCommand() (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:     "list-auth-servers",
		Short:   "List available authentication servers",
		Args:    cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			authServers := RunConfig.Settings.AuthServers
			if authServers != nil {
				table := tablewriter.NewWriter(os.Stdout)
				table.SetHeader([]string{"Name", "Client ID", "Issuer"})

				// For each type name, draw a table with the relevant profileName keys
				for authServerName, authServer := range authServers {
					table.Append([]string{authServerName, authServer.ClientID, authServer.Issuer})
				}
				table.Render()
			} else {
				fmt.Printf("No authentication servers configured. Use `%s auth addServer` to add one.\n", Root.CommandPath())
			}
		},
	}
	return
}

// WARNING: This does not support array indices in its current implementation.
func runConfig(filePath string, topLevel interface{}, args []string) {
	logger := log.With().Logger()

	path := args[0]
	if len(args) == 1 {
		currentValue, err := getValueFromPath(topLevel, path)
		if err != nil {
			logger.Fatal().Err(err).Msgf("could not find value at path %q", path)
			return
		}
		fmt.Printf("%v\n", currentValue.Interface())
		return
	}

	reflectType, err := getTypeFromPath(reflect.TypeOf(topLevel), path)
	if err != nil {
		logger.Fatal().Err(err).Msgf("%q is not a valid path", path)
	}
	valueString := args[1]
	value, err := parseNewValue(valueString, reflectType)
	if err != nil {
		logger.Fatal().Err(err).Msgf("an error occurred parsing value %q", valueString)
	}

	updates := make(map[string]interface{})
	updates[path] = value
	err = RunConfig.write(filePath, updates)
	if err != nil {
		logger.Fatal().Err(err).Msgf("an error occurred writing updates to %q", filePath)
	}
}

func buildSettingsGetCommand() (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:   "get <config-path>",
		Short: `Get a value from settings.toml using a "." separated path.`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			runConfig(RunConfig.settingsPath, RunConfig.Settings, args)
		},
	}
	return
}
func buildSettingsSetCommand() (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:   "set <config-path> <value>",
		Short: "Set a value in settings.toml using a \".\" separated path.",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			runConfig(RunConfig.settingsPath, RunConfig.Settings, args)
		},
	}
	return
}

var errTagNotFound = errors.New("tag not found")
var errUnsupportedTag = errors.New("unsupported tag")

func getValueOfTagField(t interface{}, tag string) (parsed interface{}, err error) {
	parsed = nil
	if t == nil {
		return
	}
	interfaceType := reflect.TypeOf(t)
	interfaceValue := reflect.ValueOf(t)
	if interfaceType.Kind() == reflect.Ptr {
		interfaceType = interfaceType.Elem()
		interfaceValue = interfaceValue.Elem()
	}
	if interfaceType.Kind() == reflect.Map {
		if interfaceValue.IsZero() {
			err = errTagNotFound
			return
		}
		elemValue := interfaceValue.MapIndex(reflect.ValueOf(tag))
		if !elemValue.IsValid() {
			err = errTagNotFound
			return
		}
		parsed = elemValue.Interface()
		return
	}
	if interfaceValue.Kind() != reflect.Struct {
		err = fmt.Errorf("unsupported interface kind %s", interfaceValue.Kind())
		return
	}
	for i := 0; i < interfaceType.NumField(); i++ {
		field := interfaceType.Field(i)
		val, ok := field.Tag.Lookup("mapstructure")
		if !ok {
			continue
		}
		firstTagValue := strings.Split(val, ",")[0]
		if firstTagValue == toSnakeCase(tag) {
			fieldValue := interfaceValue.Field(i)
			parsed = fieldValue.Interface()
			return
		}
	}
	err = errTagNotFound
	return
}

func getTypeOfTagField(interfaceType reflect.Type, tag string) (reflectType reflect.Type, err error) {
	if interfaceType.Kind() == reflect.Ptr {
		interfaceType = interfaceType.Elem()
	}
	if interfaceType.Kind() == reflect.Map {
		reflectType = interfaceType.Elem()
		return
	}
	if interfaceType.Kind() != reflect.Struct {
		err = fmt.Errorf("unsupported interface kind %s", interfaceType.Kind())
		return
	}
	for i := 0; i < interfaceType.NumField(); i++ {
		field := interfaceType.Field(i)
		val, ok := field.Tag.Lookup("mapstructure")
		if !ok {
			continue
		}
		firstTagValue := strings.Split(val, ",")[0]
		if firstTagValue == toSnakeCase(tag) {
			reflectType = field.Type
			return
		}
	}
	return nil, errTagNotFound
}


func getValueFromPath(value interface{}, path string) (reflectValue reflect.Value, err error) {
	parts := strings.Split(path, ".")

	cursor := value
	for _, part := range parts {
		cursor, err = getValueOfTagField(cursor, part)
		if err != nil {
			reflectValue = reflect.ValueOf(cursor)
			return
		}
	}
	reflectValue = reflect.ValueOf(cursor)
	return
}

func getTypeFromPath(parent reflect.Type, path string) (reflectType reflect.Type, err error) {
	parts := strings.Split(path, ".")

	reflectType = parent
	for _, part := range parts {
		reflectType, err = getTypeOfTagField(reflectType, part)
		if err != nil {
			return
		}
	}
	return
}

func parseNewValue(newValue interface{}, reflectType reflect.Type) (parsed interface{}, err error) {
	switch reflectType.Kind() {
	case reflect.Int:
		return cast.ToIntE(newValue)
	case reflect.Float64:
		return cast.ToFloat64E(newValue)
	case reflect.String:
		return cast.ToString(newValue), nil
	case reflect.Bool:
		return cast.ToBoolE(newValue)
	default:
		return nil, errUnsupportedTag
	}
}
