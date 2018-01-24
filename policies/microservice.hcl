# Allow a token to generate TLS certificates from the PKI secret backend
# for the client role.
path "pki/issue/client" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Allow a token to generate TLS certificates from the PKI secret backend
# for the server role.
path "pki/issue/server" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Allow token to read secret
# cert path=/secret/certs/<namespace>/<service-name>
path "secret/certs/vault-controller/server" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/certs/vault-controller/client" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
