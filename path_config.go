package secrettesting

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/vault/sdk/rotation"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/automatedrotationutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathConfig adds the defined paths to the backend.
func pathConfig(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: PathConfig,
			Fields:  configFields(),
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathConfigCrupdate,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "configure",
					},
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathConfigCrupdate,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "configure",
					},
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathConfigRead,
				},
			},
			HelpSynopsis:    "configure path",
			HelpDescription: `configure path`,
			ExistenceCheck:  b.pathConfigExistence,
		},
	}
}

func (b *backend) pathConfigCrupdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// get old config
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if v, ok := data.GetOk("message"); ok {
		config.Message = v.(string)
	}

	if v, ok := data.GetOk("username"); ok {
		config.Username = v.(string)
	}

	if v, ok := data.GetOk("password"); ok {
		config.Password = v.(string)
	}

	if v, ok := data.GetOk("low_check"); ok {
		b.Logger().Info("low_check", "value", v.(int))
		config.LowCheck = v.(int)
	}

	config.ParseAutomatedRotationFields(data)

	if config.ShouldDeregisterRotationJob() {
		// rotOp = rotation.PerformedDeregistration
		deregisterReq := &rotation.RotationJobDeregisterRequest{
			MountPoint: req.MountPoint,
			ReqPath:    req.Path,
		}
		err := b.System().DeregisterRotationJob(ctx, deregisterReq)
		if err != nil {
			return logical.ErrorResponse("error de-registering rotation job: %s", err), nil
		}
	} else if config.ShouldRegisterRotationJob() {
		// rotOp = rotation.PerformedRegistration
		req := &rotation.RotationJobConfigureRequest{
			Name:             rootRotationJobName,
			MountPoint:       req.MountPoint,
			ReqPath:          req.Path,
			RotationSchedule: config.RotationSchedule,
			RotationWindow:   config.RotationWindow,
			RotationPeriod:   config.RotationPeriod,
		}

		_, err := b.System().RegisterRotationJob(ctx, req)
		if err != nil {
			return logical.ErrorResponse("error registering rotation job: %s", err), nil
		}
	}

	bt, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, &logical.StorageEntry{
		Key:   PathConfig,
		Value: bt,
	})
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	responseData := map[string]interface{}{}
	responseData["message"] = config.Message
	responseData["low_check"] = config.LowCheck
	responseData["high_check"] = config.HighCheck
	responseData["username"] = config.Username
	responseData["password"] = config.Password // normally you wouldn't do this but this is fake data for testing

	config.PopulateAutomatedRotationData(responseData)

	return &logical.Response{
		Data: responseData,
	}, nil
}

func (b *backend) pathConfigExistence(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	se, err := req.Storage.Get(ctx, PathConfig)
	if err != nil {
		return false, err
	}

	return (se != nil), nil
}

func configFields() map[string]*framework.FieldSchema {
	fields := map[string]*framework.FieldSchema{
		"message": {
			Type: framework.TypeString,
		},
		"low_check": {
			Type: framework.TypeInt,
		},
		"high_check": {
			Type: framework.TypeInt,
		},
		"username": {
			Type: framework.TypeString,
		},
		"password": {
			Type: framework.TypeString,
		},
	}

	// add the rotation_window etc fields to the request schema
	automatedrotationutil.AddAutomatedRotationFields(fields)

	return fields
}

func getConfig(ctx context.Context, storage logical.Storage) (*configData, error) {
	config := &configData{}

	se, err := storage.Get(ctx, PathConfig)
	if err != nil {
		return nil, err
	}
	if se == nil {
		return config, nil
	}

	err = json.Unmarshal(se.Value, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

// configData has all the data we store for configuration.
type configData struct {
	Message   string `json:"message"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	LowCheck  int    `json:"low_check"`
	HighCheck int    `json:"high_check"`

	automatedrotationutil.AutomatedRotationParams
}
