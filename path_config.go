package secrettesting

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/automatedrotationutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathConfig adds the defined paths to the backend.
func pathConfig(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "config",
			Fields:  configFields(),
			Operations: map[logical.Operation]framework.OperationHandler{
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
	se, err := req.Storage.Get(ctx, "config")
	if err != nil {
		return nil, err
	}

	config := &configData{}

	if se != nil {
		err = json.Unmarshal(se.Value, config)
		if err != nil {
			return nil, err
		}
	}

	if v, ok := data.GetOk("message"); ok {
		config.Message = v.(string)
	}

	config.ParseAutomatedRotationFields(data)

	bt, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, &logical.StorageEntry{
		Key:   "config",
		Value: bt,
	})
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// grab the config struct
	se, err := req.Storage.Get(ctx, "config")
	if err != nil {
		return nil, err
	}

	config := &configData{}
	err = json.Unmarshal(se.Value, config)
	if err != nil {
		return nil, err
	}

	responseData := map[string]interface{}{}
	responseData["message"] = config.Message

	config.PopulateAutomatedRotationData(responseData)

	return &logical.Response{
		Data: responseData,
	}, nil
}

func (b *backend) pathConfigExistence(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	se, err := req.Storage.Get(ctx, "config")
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
	}

	// add the rotation_window etc fields to the request schema
	automatedrotationutil.AddAutomatedRotationFields(fields)

	return fields
}

// configData has all the data we store for configuration.
type configData struct {
	Message string `json:"message"`

	automatedrotationutil.AutomatedRotationParams
}
