package secrettesting

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/automatedrotationutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/rotation"
	"github.com/pkg/errors"
)

// genericNameWithForwardSlashRegex is a regex which requires a role name. The
// role name can include any number of alphanumeric characters separated by
// forward slashes.
func genericNameWithForwardSlashRegex(name string) string {
	return fmt.Sprintf(`(/(?P<%s>\w(([\w-./]+)?\w)?))`, name)
}

func pathStaticRole(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: PathStaticRole + genericNameWithForwardSlashRegex("name"),
			Fields:  staticRoleFields(),
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathStaticRoleCrupdate,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathStaticRoleCrupdate,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathStaticRoleRead,
				},
			},
			ExistenceCheck: b.pathStaticRoleExistence,
		},
	}
}

func staticRoleFields() map[string]*framework.FieldSchema {
	fields := map[string]*framework.FieldSchema{
		"name": {
			Type: framework.TypeLowerCaseString,
		},
		"username": {
			Type: framework.TypeString,
		},
		"password": {
			Type: framework.TypeString,
		},
	}

	automatedrotationutil.AddAutomatedRotationFields(fields)

	return fields
}

func (b *backend) pathStaticRoleCrupdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name, ok := data.GetOk("name")
	if !ok {
		return nil, errors.New("no name")
	}
	role, err := getStaticRole(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}

	if v, ok := data.GetOk("username"); ok {
		role.Username = v.(string)
	}

	if v, ok := data.GetOk("password"); ok {
		role.Password = v.(string)
	}

	role.ParseAutomatedRotationFields(data)

	if role.ShouldDeregisterRotationJob() {
		// rotOp = rotation.PerformedDeregistration
		deregisterReq := &rotation.RotationJobDeregisterRequest{
			MountPoint: req.MountPoint,
			ReqPath:    req.Path,
		}
		err := b.System().DeregisterRotationJob(ctx, deregisterReq)
		if err != nil {
			return logical.ErrorResponse("error de-registering rotation job: %s", err), nil
		}
	} else if role.ShouldRegisterRotationJob() {
		// rotOp = rotation.PerformedRegistration
		req := &rotation.RotationJobConfigureRequest{
			Name:             staticRotationJobName,
			MountPoint:       req.MountPoint,
			ReqPath:          req.Path,
			RotationSchedule: role.RotationSchedule,
			RotationWindow:   role.RotationWindow,
			RotationPeriod:   role.RotationPeriod,
		}

		_, err := b.System().RegisterRotationJob(ctx, req)
		if err != nil {
			return logical.ErrorResponse("error registering rotation job: %s", err), nil
		}
	}

	return nil, nil
}

func (b *backend) pathStaticRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name, ok := data.GetOk("name")
	if !ok {
		return nil, errors.New("no name")
	}
	role, err := getStaticRole(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}

	d := map[string]interface{}{}
	d["username"] = role.Username
	d["password"] = role.Password

	role.PopulateAutomatedRotationData(d)

	return &logical.Response{
		Data: d,
	}, nil
}

func (b *backend) pathStaticRoleExistence(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	return false, nil
}

func getStaticRole(ctx context.Context, storage logical.Storage, name string) (*staticRole, error) {
	se, err := storage.Get(ctx, PathStaticRole+"/"+name)
	if err != nil {
		return nil, err
	}

	role := &staticRole{}
	if se == nil {
		return role, nil
	}

	err = json.Unmarshal(se.Value, role)
	if err != nil {
		return nil, err
	}

	return role, nil
}

type staticRole struct {
	Username string `json:"username"`
	Password string `json:"password"`

	automatedrotationutil.AutomatedRotationParams
}
