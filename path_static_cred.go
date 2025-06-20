package secrettesting

import (
	"context"
	"errors"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/rotation"
	"time"
)

func pathStaticCred(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: PathStaticCred + genericNameWithForwardSlashRegex("name"),
			Fields:  staticCredFields(),
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathStaticCredRead,
				},
			},
			//ExistenceCheck: b.pathStaticCredExistence,
		},
	}
}

func staticCredFields() map[string]*framework.FieldSchema {
	fields := map[string]*framework.FieldSchema{
		"name": {
			Type: framework.TypeLowerCaseString,
		},
	}

	return fields
}

func (b *backend) pathStaticCredRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name, ok := data.GetOk("name")

	b.Logger().Info("looking up entry", "name", name)

	if !ok {
		return nil, errors.New("no name")
	}
	role, err := getStaticRole(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}

	var t time.Time
	var checkedTTL bool
	if role.HasRotationParams() {
		t, err = b.System().GetRotationInformation(ctx, &rotation.RotationInfoRequest{
			// the static-role method is what sets up the credential, so we use that to look up the credential in the rotation manager.
			ReqPath: PathStaticRole + "/" + name.(string),
		})
		if err != nil {
			panic(err)
		}
		checkedTTL = true
	}

	out := map[string]interface{}{}
	out["username"] = role.Username
	out["password"] = role.Password
	if checkedTTL {
		out["ttl"] = t.Sub(time.Now()).Seconds()
		out["expire_time"] = t.Format(time.ANSIC)
	}

	return &logical.Response{
		Data: out,
	}, nil
}
