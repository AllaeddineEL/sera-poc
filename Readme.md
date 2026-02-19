# Install Vault Enterprise 
sudo su

apt update -y

curl -OL https://releases.hashicorp.com/vault/1.21.3+ent/vault_1.21.3+ent_linux_amd64.zip

unzip -d 1.21.3+ent vault_1.21.3+ent_linux_amd64.zip

mv 1.21.3+ent/vault /usr/local/bin

rm -R 1.21.3+ent/ vault_1.21.3+ent_linux_amd64.zip

# Start Vault server in dev mode

export VAULT_LICENSE_PATH=./vault.hclic 
nohup vault server -dev -dev-root-token-id="root" -dev-listen-address="0.0.0.0:8200"

# Use AppRole authentication

1. Enable the AppRole auth method:

```bash
vault auth enable approle
```

```bash
cat <<-EOF > | vault policy write vault-iis-agent
# Issue new certs
path "pki_int/issue/win-iis" {
    capabilities = ["list", "read", "create", "update", "delete"]
}

# Revoke certs
path "pki_int/revoke" {
    capabilities = [ "list", "read", "update", "delete"]
}
EOF
```

2. Create policy for Vault Agent

```bash
cat <<-EOF > ./vault-iis-agent-policy.hcl
# Issue new certs
path "pki_int/issue/win-iis" {
    capabilities = ["list", "read", "create", "update", "delete"]
}

# Revoke certs
path "pki_int/revoke" {
    capabilities = [ "list", "read", "update", "delete"]
}
EOF
```
3. Upload Vault agent policy

```bash
vault policy write vault-iis-agent ./vault-iis-agent-policy.hcl
```
4. Create a named role:

```bash
vault write auth/approle/role/iis-role token_policies="default,vault-iis-agent" \
    token_ttl=1h token_max_ttl=4h


vault write auth/approle/role/iis-role \
    token_type=batch \
    secret_id_ttl=10m \
    token_ttl=20m \
    token_max_ttl=30m \
    secret_id_num_uses=40 \
    policies="default","vault-iis-agent"
```

```bash
vault read auth/approle/role/iis-role
```


5. Fetch the RoleID of the AppRole:

```bash
vault read auth/approle/role/iis-role/role-id
```

6. Get a SecretID issued against the AppRole
```bash
vault write -f auth/approle/role/iis-role/secret-id
```
7. Login with AppRole

```bash
vault write auth/approle/login role_id="" \
    secret_id=""
```

"C:\Program Files\Vault\vault.exe" agent -config="C:\ProgramData\Vault\agent.hcl" -log-level=debug