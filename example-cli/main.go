package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"

	"github.com/rigetti/openapi-cli-generator/cli"
)

func main() {
	config := &cli.Config{
		AppName:   "<no value>",
		EnvPrefix: "EXAMPLE",
		Version:   "1.0.0",
	}
	cli.Init(config)

	defaults := cli.NewGlobalFlagDefaults("http://localhost:8000")
	globalFlags, err := cli.MakeAndParseGlobalFlags(defaults)
	if err != nil {
		log.Fatal(err)
	}

	openapiRegister(false, globalFlags)

	err = cli.InitConfiguration("EXAMPLE", getTOMLFilePath("settings"), getTOMLFilePath("secrets"), globalFlags)
	if err != nil {
		log.Fatal(err)
	}

	cli.AddConfigCommands(cli.Root)
	cli.AddAuthCommands(cli.Root)

	cli.Root.Execute()
}

func getTOMLFilePath(filename string) string {
	envValue := os.Getenv(strings.ToUpper(fmt.Sprintf("%s_%s_PATH", "EXAMPLE", filename)))
	if envValue != "" {
		return envValue
	}
	return fmt.Sprintf("%s/.%s/%s.toml", userHomeDir(), strings.ToLower("EXAMPLE"), filename)
}

func userHomeDir() string {
	if runtime.GOOS == "windows" {
		home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		return home
	}
	return os.Getenv("HOME")
}
