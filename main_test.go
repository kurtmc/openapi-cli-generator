// Note: do not run with `go test`. Instead use the `./test.sh` script!
package main_test

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	// Set up a test server that implements the API described in
	// `./example-cli/openapi.yaml` and start it before running the tests.
	server := &http.Server{Addr: ":8005", Handler: http.DefaultServeMux}

	http.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			panic(err)
		}

		ct := r.Header.Get("Content-Type")
		if ct != "" {
			w.Header().Add("Content-Type", ct)
		}

		// For the test, add the param values to the echoed response.
		var decoded map[string]interface{}
		json.Unmarshal(body, &decoded)

		q := r.URL.Query().Get("q")
		if q != "" {
			decoded["q"] = q
		}

		rid := r.Header.Get("X-Request-ID")
		if rid != "" {
			decoded["request-id"] = rid
		}

		marshalled, _ := json.Marshal(decoded)
		w.Write(marshalled)
	})

	go func() {
		server.ListenAndServe()
	}()
	defer server.Shutdown(context.Background())

	os.Exit(m.Run())
}

func TestEchoSuccess(t *testing.T) {
	// Call the precompiled executable CLI to hit our test server.
	// Note, `echo-query` has `x-cli-name` set in OAS definition.

	out, err := exec.Command("sh", "-c", "example-cli echo hello: world --api-url http://127.0.0.1:8005 --echo-query=foo --x-request-id bar").CombinedOutput()
	t.Log(string(out))
	require.NoError(t, err)

	assert.JSONEq(t, "{\"hello\": \"world\", \"q\": \"foo\", \"request-id\": \"bar\"}", string(out))
}

func TestConfiguration(t *testing.T) {
	t.Run("can set and read settings", func(t *testing.T) {
		var out []byte
		var err error
		out, err = exec.Command("sh", "-c", "example-cli settings set default_profile_name bogus").CombinedOutput()
		t.Log(string(out))
		require.NoError(t, err)

		out, err = exec.Command("sh", "-c", "example-cli settings get default_profile_name").CombinedOutput()
		t.Log(string(out))
		require.NoError(t, err)
		assert.Equal(t, "bogus", strings.TrimSpace(string(out)))
	})
}

func TestAuth(t *testing.T) {
	t.Run("can add, remove and list auth servers", func(t *testing.T) {
		var out []byte
		var err error
		out, err = exec.Command("sh", "-c", "example-cli settings add-auth-server auth1 --issuer https://auth.test.sh --client-id 01").CombinedOutput()
		t.Log(string(out))
		require.NoError(t, err)

		out, err = exec.Command("sh", "-c", "example-cli settings list-auth-servers").CombinedOutput()
		t.Log(string(out))
		require.NoError(t, err)
		assert.Contains(t,  string(out),"| auth1   |        01 | https://auth.test.sh |")

		out, err = exec.Command("sh", "-c", "example-cli settings remove-auth-server auth1").CombinedOutput()
		t.Log(string(out))
		require.NoError(t, err)
		assert.NotContains(t,  string(out),"| auth1   |        01 | https://auth.test.sh |")
	})

	t.Run("can list, parse, and remove credentials", func(t *testing.T) {
		var out []byte
		var err error
		out, err = exec.Command("sh", "-c", "example-cli secrets list-credentials").CombinedOutput()
		t.Log(string(out))
		require.NoError(t, err)
		assert.Contains(t,  string(out),"| default |           |          |")
		require.Contains(t,  string(out),"| test    | test-cid  | test-iss |")

		out, err = exec.Command("sh", "-c", "example-cli secrets print-claims test").CombinedOutput()
		t.Log(string(out))
		require.NoError(t, err)
		assert.Contains(t, string(out), `"cid": "test-cid"`)
		assert.Contains(t, string(out), `"iss": "test-iss",`)

		out, err = exec.Command("sh", "-c", "example-cli secrets remove-credentials test").CombinedOutput()
		t.Log(string(out))
		require.NoError(t, err)

		out, err = exec.Command("sh", "-c", "example-cli secrets list-credentials").CombinedOutput()
		t.Log(string(out))
		require.NoError(t, err)
		assert.Contains(t,  string(out),"| default |           |        |")
		assert.NotContains(t,  string(out),"| test    | test-cid  | test-iss |")
	})

	t.Run("can get and set existing secrets.toml values", func(t *testing.T) {
		var out []byte
		var err error
		out, err = exec.Command("sh", "-c", "example-cli secrets get credentials.default.token_payload.access_token").CombinedOutput()
		t.Log(string(out))
		require.NoError(t, err)
		assert.Equal(t, "access", strings.TrimSpace(string(out)))

		out, err = exec.Command("sh", "-c", "example-cli secrets get credentials.default.token_payload.refresh_token").CombinedOutput()
		t.Log(string(out))
		require.NoError(t, err)
		assert.Equal(t, "refresh", strings.TrimSpace(string(out)))
	})

	t.Run("can get and set new secrets.toml values", func(t *testing.T) {
		var out []byte
		var err error
		out, err = exec.Command("sh", "-c", "example-cli secrets set credentials.new.token_payload.access_token newAccess").CombinedOutput()
		t.Log(string(out))
		require.NoError(t, err)
		assert.Equal(t, "", strings.TrimSpace(string(out)))

		out, err = exec.Command("sh", "-c", "example-cli secrets get credentials.new.token_payload.access_token").CombinedOutput()
		t.Log(string(out))
		require.NoError(t, err)
		assert.Equal(t, "newAccess", strings.TrimSpace(string(out)))
	})
}

func TestGlobalFlags(t *testing.T) {
	t.Run("global flags are printed separately", func(t *testing.T) {
		out, _ := exec.Command("sh", "-c", "example-cli echo --help").CombinedOutput()
		t.Log(string(out))
		assert.Contains(t, string(out), "Global Flags:")
		assert.Contains(t, string(out), "--api-url string")
		assert.Contains(t, string(out), "--auth-server-name string")
		assert.Contains(t, string(out), "--headers stringArray")
		assert.Contains(t, string(out), "--credentials-name string")
		assert.Contains(t, string(out), "--output-format string")
		assert.Contains(t, string(out), "--profile-name string")
		assert.Contains(t, string(out), "--raw")
	})

}


