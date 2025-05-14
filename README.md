##

This is a testing plugin for Hashicorp Vault. It mostly exists as a way to have features without worrying about
having an external service, or modifying a plugin that has a lot of other considerations. I assume if you're looking
at this you know at least a little about plugin development.

## Building
```sh
make dev
```

To register:
```sh
$ SHA256=$(openssl dgst -sha256 $GOPATH/vault-plugin-secrets-testing | cut -d ' ' -f2)
$ vault plugin register \
        -sha256=$SHA256 \
        -command="vault-plugin-secrets-testing" \
        secrets testing
...