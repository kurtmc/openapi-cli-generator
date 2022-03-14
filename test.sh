#!/bin/sh

set -ev

# Build `openapi-cli-generator`
go generate
go install

# Generate our test example app
cd example-cli
rm -rf main.go
openapi-cli-generator init example
openapi-cli-generator generate openapi.yaml
sed -i'' -e 's/\/\/ TODO: Add register commands here./openapiRegister(false)/' main.go
go install
cd ..

cat >$HOME/.example/settings.toml <<EOL
[auth_servers]
[auth_servers.default]
client_id = ""
issuer = ""

[profiles]
[profiles.default]
api_url = "https://www.test.sh"
EOL

cat >$HOME/.example/secrets.toml <<EOL
[credentials]
[credentials.default]
[credentials.default.token_payload]
access_token = "access"
refresh_token = "refresh"
token_type = "Bearer"
[credentials.test]
[credentials.test.token_payload]
access_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMjIsImNpZCI6InRlc3QtY2lkIiwiaXNzIjoidGVzdC1pc3MifQ.lyeqYKkwCiJNTqnaVwIiiTtb7irfhndkK6z-unll8Oo"
refresh_token = "refresh"
token_type = "Bearer"
EOL

# Run all the tests!
go test "$@" ./...
