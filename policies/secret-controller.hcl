# Allow token to read secret
path "secret/certs/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
