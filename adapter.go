package boltadapter

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/casbin/casbin/v2/model"
	bolt "github.com/coreos/bbolt"
)

// CasbinRule represents a Casbin rule line.
type CasbinRule struct {
	Key   string `json:"key"`
	PType string `json:"p_type"`
	V0    string `json:"v0"`
	V1    string `json:"v1"`
	V2    string `json:"v2"`
	V3    string `json:"v3"`
	V4    string `json:"v4"`
	V5    string `json:"v5"`
}

type adapter struct {
	db            *bolt.DB
	bucket        []byte
	builtinPolicy string
}

// NewAdapter creates a new adapter. It assumes that the Bolt DB is already open. A bucket name is required and
// represents the Bolt bucket to save the data into. like to save to. The builtinPolicy is a string representation
// of a Casbin csv policy definition. If left builtinPolicy will not be used.
func NewAdapter(db *bolt.DB, bucket string, builtinPolicy string) (*adapter, error) {
	if bucket == "" {
		return nil, errors.New("must provide a bucket")
	}

	adapter := &adapter{
		db:            db,
		bucket:        []byte(bucket),
		builtinPolicy: builtinPolicy,
	}

	if err := adapter.init(); err != nil {
		return nil, err
	}

	return adapter, nil
}

func (a *adapter) init() error {
	return a.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(a.bucket)
		return err
	})
}

// LoadPolicy performs a scan on the bucket and individually loads every line into the Casbin model.
// Not particularity efficient but should only be required on when you application starts up as this adapter can
// leverage auto-save functionality.
func (a *adapter) LoadPolicy(model model.Model) error {
	if a.builtinPolicy != "" {
		for _, line := range strings.Split(a.builtinPolicy, "\n") {
			if err := loadCsvPolicyLine(strings.TrimSpace(line), model); err != nil {
				return err
			}
		}
	}

	return a.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(a.bucket)

		return bucket.ForEach(func(k, v []byte) error {
			var line CasbinRule
			if err := json.Unmarshal(v, &line); err != nil {
				return err
			}
			loadPolicy(line, model)
			return nil
		})
	})
}

// SavePolicy iterates through the entire model and individually saves each line.
// Note: should not be needed when using auto-save function.
func (a *adapter) SavePolicy(model model.Model) error {
	return a.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(a.bucket)

		for ptype, ast := range model["p"] {
			for _, line := range ast.Policy {
				if err := a.putLine(bucket, ptype, line); err != nil {
					return err
				}
			}
		}

		for ptype, ast := range model["g"] {
			for _, line := range ast.Policy {
				if err := a.putLine(bucket, ptype, line); err != nil {
					return err
				}
			}
		}

		return nil
	})
}
