package boltadapter

import (
	"encoding/json"
	"fmt"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/mmcloughlin/meow"
	bolt "go.etcd.io/bbolt"
	"strings"
)

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
	db     *bolt.DB
	bucket []byte
}

func NewAdapter(db *bolt.DB, bucket string) *adapter {
	return &adapter{
		db:     db,
		bucket: []byte(bucket),
	}
}

func (a *adapter) Open() error {
	return a.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(a.bucket)
		return err
	})
}

func loadPolicyLine(line CasbinRule, model model.Model) {
	lineText := line.PType
	if line.V0 != "" {
		lineText += ", " + line.V0
	}
	if line.V1 != "" {
		lineText += ", " + line.V1
	}
	if line.V2 != "" {
		lineText += ", " + line.V2
	}
	if line.V3 != "" {
		lineText += ", " + line.V3
	}
	if line.V4 != "" {
		lineText += ", " + line.V4
	}
	if line.V5 != "" {
		lineText += ", " + line.V5
	}

	persist.LoadPolicyLine(lineText, model)
}

func policyKey(ptype string, rule []string) string {
	data := strings.Join(append([]string{ptype}, rule...), ",")
	sum := meow.Checksum(0, []byte(data))
	return fmt.Sprintf("%x", sum)
}

func savePolicyLine(ptype string, rule []string) *CasbinRule {
	line := &CasbinRule{PType: ptype}

	l := len(rule)
	if l > 0 {
		line.V0 = rule[0]
	}
	if l > 1 {
		line.V1 = rule[1]
	}
	if l > 2 {
		line.V2 = rule[2]
	}
	if l > 3 {
		line.V3 = rule[3]
	}
	if l > 4 {
		line.V4 = rule[4]
	}
	if l > 5 {
		line.V5 = rule[5]
	}

	line.Key = policyKey(ptype, rule)

	return line
}

func (a *adapter) LoadPolicy(model model.Model) error {
	return a.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(a.bucket)

		return bucket.ForEach(func(k, v []byte) error {
			var line CasbinRule
			if err := json.Unmarshal(v, &line); err != nil {
				return err
			}
			loadPolicyLine(line, model)
			return nil
		})
	})
}

func (a *adapter) AddPolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)

	return a.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(a.bucket)

		key := []byte(line.Key)

		bts, err := json.Marshal(line)
		if err != nil {
			return err
		}

		return bucket.Put(key, bts)
	})
}

func (a *adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)

	return a.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(a.bucket)

		return bucket.Delete([]byte(line.Key))
	})
}

func (a *adapter) SavePolicy(model model.Model) error {
	panic("not supported")
}

func (a *adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	panic("not supported")
}
