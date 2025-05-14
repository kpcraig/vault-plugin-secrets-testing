package secrettesting

import (
	"context"
	"fmt"
	"strings"

	"github.com/pkg/errors"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type backend struct {
	*framework.Backend

	// include other locally necessary fields below here
}

// Factory creates a backend - this is part of the hashicorp plugin sdk
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(conf)
	err := b.Setup(ctx, conf)
	if err != nil {
		return nil, err
	}

	return b, nil
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
			pathStaticRole(b),
			//		b.pathStaticCredsCreate(),
			//		b.pathListStaticRoles(),
			// b.pathRotateCredentials(),
		),
		BackendType: logical.TypeLogical,
		//
		RotateCredential: b.rotateCredential,
		InitializeFunc:   b.initialize,
		RunningVersion:   "v" + Version,
	}

	return b
}

func (b *backend) rotateCredential(ctx context.Context, req *logical.Request) error {
	b.Logger().Info("we got a rotate call", "req", req)

	return nil
}

// initialize sets up a storage entry that tracks how many times initalize has been called.
func (b *backend) initialize(ctx context.Context, req *logical.InitializationRequest) error {
	se, err := req.Storage.Get(ctx, InitializeCheckEntry)
	if err != nil {
		return errors.Wrapf(err, "couldn't retrieve check entry from storage")
	}
	if se == nil {
		// first time we've entered initialize (probably on the registry call)
		err = req.Storage.Put(ctx, &logical.StorageEntry{
			Key:   InitializeCheckEntry,
			Value: []byte{1},
		})
		if err != nil {
			return err
		}

		b.Logger().Info("initialize", "count", 1)

		return nil
	}

	// this is the plus oneth time
	times := se.Value[0] + 1

	// retrive config
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return err
	}
	if config != nil {
		if config.LowCheck != 0 && int(times) > config.LowCheck {
			// increment anyway
			se.Value = []byte{times}
			err = req.Storage.Put(ctx, se)
			if err != nil {
				return err
			}
			return fmt.Errorf("artificial initialize failure due to initialize count being higher than low_check: %d vs %d", times, config.LowCheck)
		}
	}

	// assume storage entry works
	se.Value = []byte{times}
	err = req.Storage.Put(ctx, se)
	if err != nil {
		return err
	}

	b.Logger().Info("initialize", "count", fmt.Sprintf("%d", se.Value[0]))

	return nil
}

const backendHelp = `
This is an example secret backend that doesn't really do anything
`
