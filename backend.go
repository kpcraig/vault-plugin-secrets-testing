package secrettesting

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type backend struct {
	*framework.Backend

	// include other locally necessary fields below here
}

// Factory creates a backend - this is part of the hashicorp plugin sdk
func Factory(_ context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	return Backend(conf), nil
}

// Backend is also traditionally defined to send configuration data in, although these days the conf itself is quite unused
func Backend(_ *logical.BackendConfig) *backend {
	b := &backend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{
				framework.WALPrefix,
			},
			SealWrapStorage: []string{
				"config",
			},
		},
		Paths: framework.PathAppend(
			pathConfig(b),
			//		b.pathStaticRoles(),
			//		b.pathStaticCredsCreate(),
			//		b.pathListStaticRoles(),
			//b.pathRotateCredentials(),
		),
		BackendType: logical.TypeLogical,
		//
		RotateCredential: b.rotateCredential,
		InitializeFunc:   b.initialize,
	}

	return b
}

func (b *backend) rotateCredential(ctx context.Context, req *logical.Request) error {
	b.Logger().Info("we got a rotate call", "req", req)

	return nil
}

func (b *backend) initialize(ctx context.Context, req *logical.InitializationRequest) error {
	return nil
}

const backendHelp = `
This is an example secret backend that doesn't really do anything
`
