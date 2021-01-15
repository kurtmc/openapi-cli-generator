package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

// execute a command against the configured CLI
func execute(cmd string) (*bytes.Buffer, error) {
	out := new(bytes.Buffer)
	Root.SetArgs(strings.Split(cmd, " "))
	Root.SetOutput(out)
	Stdout = out
	Stderr = out
	err := Root.Execute()
	return out, err
}

func TestHelpCommands(t *testing.T) {
	Init(&Config{
		AppName: "test",
		Version: "1.0.0",
	})
	Root.AddCommand(
		BuildHelpConfigCommand("test"), BuildHelpInputCommand(),
	)

	out, err := execute("help-config")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(out.String())
	assert.Contains(t, out.String(), "CLI Configuration")

	out, err = execute("help-input")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(out.String())
	assert.Contains(t, out.String(), "CLI Request Input")
}

func TestPreRun(t *testing.T) {
	Init(&Config{
		AppName: "test",
		Version: "1.0.0",
	})
	Root.AddCommand(
		BuildHelpConfigCommand("test"), BuildHelpInputCommand(),
	)

	ran := false
	PreRun = func(cmd *cobra.Command, args []string) error {
		ran = true
		return nil
	}

	Root.Run = func(cmd *cobra.Command, args []string) {
		// Do nothing, but also don't error.
	}

	_, err := execute("")
	if err != nil {
		t.Fatal(err)
	}

	assert.True(t, ran)
}
