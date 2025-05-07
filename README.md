## Getting Started

This is a [Vault plugin](https://developer.hashicorp.com/vault/docs/plugins)
and is meant to work with Vault. This guide assumes you have already installed
Vault and have a basic understanding of how Vault works.

Otherwise, first read this guide on how to [get started with
Vault](https://developer.hashicorp.com/vault/tutorials/getting-started/getting-started-install).


## Usage

[//]: <> (Provide usage instructions and/or links to this plugin)

## Developing

If you wish to work on this plugin, you'll first need
[Go](https://www.golang.org) installed on your machine.

If you're developing for the first time, run `make bootstrap` to install the
necessary tools. Bootstrap will also update repository name references if that
has not been performed ever before.

```sh
$ make bootstrap
```

To compile a development version of this plugin, run `make` or `make dev`.
This will put the plugin binary in the `bin` and `$GOPATH/bin` folders. `dev`
mode will only generate the binary for your platform and is faster:

```sh
$ make dev
```

Put the plugin binary into a location of your choice. This directory
will be specified as the [`plugin_directory`](https://developer.hashicorp.com/vault/docs/configuration#plugin_directory)
in the Vault config used to start the server.

```hcl
# config.hcl
plugin_directory = "path/to/plugin/directory"
...
```

Start a Vault server with this config file:

```sh
$ vault server -dev -config=path/to/config.hcl ...
...
```

Once the server is started, register the plugin in the Vault server's [plugin catalog](https://developer.hashicorp.com/vault/docs/plugins/plugin-architecture#plugin-catalog):

```sh
$ SHA256=$(openssl dgst -sha256 $GOPATH/vault-plugin-secrets-myplugin | cut -d ' ' -f2)
$ vault plugin register \
        -sha256=$SHA256 \
        -command="vault-plugin-secrets-myplugin" \
        secrets myplugin
...
Success! Data written to: sys/plugins/catalog/myplugin
```

Enable the secrets engine to use this plugin:

```sh
$ vault secrets enable myplugin
...

Successfully enabled 'plugin' at 'myplugin'!
```

### Tests

To run the tests, invoke `make test`:

```sh
$ make test
```

You can also specify a `TESTARGS` variable to filter tests like so:

```sh
$ make test TESTARGS='-run=TestConfig'
```

[//]: <> (Specify any other test instructions such as acceptance/integration tests)
