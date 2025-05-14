##

This is a testing plugin for Hashicorp Vault. It mostly exists as a way to have features without worrying about
having an external service, or modifying a plugin that has a lot of other considerations. I assume if you're looking
at this you know at least a little about plugin development.

To the extent that it matters, this was written for my job at Hashicorp and as such is their code.

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
```

## Usage
### Initialization Tripwire
One feature this plugin has is a "tripwire" setting that will cause it to fail to initialize after
a specified number of initialization attempts. Set the line by setting the `low_check` value to a non-zero in the root config:

```sh
vault write testing/config low_check=2
```

After that many initializations (the initial registration is the first), the plugin will fail to initialize, in
particular during reload calls:

```sh
vault plugin reload -type=secret -plugin=testing -scope=global
```

###
Another configuration is `rotation_wait` - setting this controls how long the plugin takes to "rotate" a credential when
it recieves the request from the Rotation Manager. This is implemented as a `time.Sleep` call.