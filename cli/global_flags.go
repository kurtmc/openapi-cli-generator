package cli

import (
	"fmt"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"os"
	"regexp"
	"strings"
)

func getBindPathsFromProfile(flagName string, args ...interface{}) (paths []string, err error) {
	if len(args) != 1 {
		err = fmt.Errorf("received unexpected arguments (%d) for flag %q", len(args), toKebabCase(flagName))
		return
	}
	settings, ok := args[0].(Settings)
	if !ok {
		err = fmt.Errorf("received non-settings arguments for flag %q", flagName)
		return
	}
	paths = make([]string, 0)
	for profileName := range settings.Profiles {
		paths = append(paths, fmt.Sprintf("profiles.%s.%s", profileName, toSnakeCase(flagName)))
	}
	if len(paths) == 0 {
		paths = append(paths, fmt.Sprintf("profiles.%s.%s", "default", toSnakeCase(flagName)))
	}
	return
}

type GlobalFlag struct {
	*pflag.Flag
	UseDefault         bool
	customGetBindPaths func(flagName string, args ...interface{}) ([]string, error)
}

var viperBindPaths = map[string]string{
	"profile-name": "default_profile_name",
	"headers": "default_headers",
}

type GlobalFlagDefaults struct {
	ProfileName     string
	AuthServerName  string
	CredentialsName string
	ApiURL          string
	OutputFormat    string
	Verbosity 		string
	Headers 		[]string
	Raw             bool
}

func NewGlobalFlagDefaults(apiURL string) GlobalFlagDefaults {
	return GlobalFlagDefaults{
		ProfileName:     "default",
		AuthServerName:  "default",
		CredentialsName: "default",
		OutputFormat:    "json",
		Verbosity: 		 "warn",
		Headers: 		 make([]string, 0),
		ApiURL:          apiURL,
	}
}

func MakeAndParseGlobalFlags(defaults GlobalFlagDefaults) (globalFlags []GlobalFlag, flagSet *pflag.FlagSet, err error) {
	flagSet = pflag.NewFlagSet("global", pflag.ContinueOnError)
	flagSet.ParseErrorsWhitelist = pflag.ParseErrorsWhitelist{
		UnknownFlags: true,
	}

	flagSet.String("profile-name", defaults.ProfileName, "")
	flagSet.String("auth-server-name", defaults.AuthServerName, "")
	flagSet.String("credentials-name", defaults.CredentialsName, "")
	flagSet.StringArray("headers", defaults.Headers, "Headers to include on outgoing requests. Each header should formatted similar to curl, for instance \"Key: Value\"")
	flagSet.String("api-url", defaults.ApiURL, "")
	flagSet.String("verbosity", defaults.Verbosity, "Log verbosity [fatal error warn info debug]")
	flagSet.StringP("output-format", "o", defaults.OutputFormat, "Output format [json yaml]")
	flagSet.BoolP("help", "h", false, "")
	flagSet.Bool("raw", defaults.Raw, "Output result of query as raw rather than an escaped JSON string or list")
	err = flagSet.Parse(os.Args[1:])
	if err != nil {
		return
	}

	globalFlags = []GlobalFlag{
		{
			UseDefault: true,
			Flag:       flagSet.Lookup("profile-name"),
		}, {
			UseDefault: true,
			customGetBindPaths: getBindPathsFromProfile,
			Flag:       flagSet.Lookup("headers"),
		}, {
			UseDefault:         true,
			customGetBindPaths: getBindPathsFromProfile,
			Flag:               flagSet.Lookup("auth-server-name"),
		}, {
			UseDefault:         true,
			customGetBindPaths: getBindPathsFromProfile,
			Flag:               flagSet.Lookup("credentials-name"),
		}, {
			UseDefault:         true,
			customGetBindPaths: getBindPathsFromProfile,
			Flag:               flagSet.Lookup("api-url"),
		}, {
			UseDefault: true,
			customGetBindPaths: func(flagName string, args ...interface{}) ([]string, error) {
				return getBindPathsFromProfile("applications.cli.output_format", args...)
			},
			Flag: flagSet.Lookup("output-format"),
		}, {
			UseDefault: true,
			customGetBindPaths: func(flagName string, args ...interface{}) ([]string, error) {
				return getBindPathsFromProfile("applications.cli.verbosity", args...)
			},
			Flag: flagSet.Lookup("verbosity"),
		},
		/*{
			TODO: Add this back - it should be globablly available as a flag but shouldn't read
			from configuration.
			customGetBindPaths: func(flagName string, args ...interface{}) ([]string, error) {
				return getBindPathsFromProfile("applications.cli.query", args...)
			},
			Flag: &pflag.Flag{
				Name:      "query",
				Shorthand: "q",
				Usage:     "Filter / project results using JMESPath",
			},
		},*/
		{
			customGetBindPaths: func(flagName string, args ...interface{}) ([]string, error) {
				return getBindPathsFromProfile("applications.cli.raw", args...)
			},
			Flag: flagSet.Lookup("raw"),
		},
	}
	return
}

func (gf GlobalFlag) getBindPaths(args ...interface{}) (paths []string, err error) {
	if gf.customGetBindPaths != nil {
		return gf.customGetBindPaths(gf.Flag.Name, args...)
	}
	paths = make([]string, 0)
	if viperBindPath, ok := viperBindPaths[gf.Flag.Name]; ok {
		paths = append(paths, viperBindPath)
		return
	}
	paths = append(paths, toSnakeCase(gf.Flag.Name))
	return
}

func (gf GlobalFlag) bindFlag(v *viper.Viper, envPrefix string, args ...interface{}) (err error) {
	paths, err := gf.getBindPaths(args...)
	if err != nil {
		return
	}
	for _, p := range paths {
		err = gf.bindFlagTo(v, p, envPrefix)
		if err != nil {
			return
		}
	}
	return
}

// bindFlagTo binds the global flag and an un-nested representation of it as
// an environment variable to all deeply nested viper paths (ie to values in
// all profiles).
func (gf GlobalFlag) bindFlagTo(v *viper.Viper, viperBindPath, envPrefix string) error {
	envVar := fmt.Sprintf("%s_%s", envPrefix, strings.ReplaceAll(strings.ToUpper(gf.Name), "-", "_"))
	err := v.BindEnv(viperBindPath, envVar)
	if err != nil {
		return err
	}

	if gf.Flag.Changed {
		return v.BindPFlag(viperBindPath, gf.Flag)
	}

	if gf.UseDefault && !v.IsSet(viperBindPath) {
		return v.BindPFlag(viperBindPath, gf.Flag)
	}
	return nil
}

var matchFirstCap = regexp.MustCompile("([A-Z])([A-Z][a-z])")
var matchAllCap = regexp.MustCompile("([a-z0-9])([A-Z])")

func toKebabCase(str string) string {
	kebab := matchFirstCap.ReplaceAllString(str, "${1}-${2}")
	kebab = matchAllCap.ReplaceAllString(kebab, "${1}-${2}")
	kebab = strings.ReplaceAll(kebab, "_", "-")
	return strings.ToLower(kebab)
}

// From https://gist.github.com/stoewer/fbe273b711e6a06315d19552dd4d33e6#gistcomment-3515624
func toSnakeCase(str string) string {
	output := matchFirstCap.ReplaceAllString(str, "${1}_${2}")
	output = matchAllCap.ReplaceAllString(output, "${1}_${2}")
	output = strings.ReplaceAll(output, "-", "_")
	return strings.ToLower(output)
}
