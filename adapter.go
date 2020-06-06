package boltadapter

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	bolt "github.com/coreos/bbolt"
	"github.com/mmcloughlin/meow"
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
	db            *bolt.DB
	bucket        []byte
	builtinPolicy string
}

// NewAdapter creates a new adapter. It assumes that the Bolt DB is already open.
func NewAdapter(db *bolt.DB, bucket string, buildinPolicy string) (*adapter, error) {
	adapter := &adapter{
		db:            db,
		bucket:        []byte(bucket),
		builtinPolicy: buildinPolicy,
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

func loadCsvPolicyLine(line string, model model.Model) error {
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}

	reader := csv.NewReader(strings.NewReader(line))
	reader.TrimLeadingSpace = true
	tokens, err := reader.Read()
	if err != nil {
		return err
	}

	key := tokens[0]
	sec := key[:1]
	model[sec][key].Policy = append(model[sec][key].Policy, tokens[1:])
	return nil
}

func policyKey(ptype string, rule []string) string {
	data := strings.Join(append([]string{ptype}, rule...), ",")
	sum := meow.Checksum(0, []byte(data))
	return fmt.Sprintf("%x", sum)
}

func savePolicyLine(ptype string, rule []string) CasbinRule {
	line := CasbinRule{PType: ptype}

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

// LoadPolicy performs a scan on the bucket to get and load all policy lines.
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
			loadPolicyLine(line, model)
			return nil
		})
	})
}

// AddPolicy inserts or updates an existing policy using the hashed policyKey as the key.
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

func (a *adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	for _, r := range rules {
		return a.AddPolicy(sec, ptype, r)
	}
	return nil
}

// RemovePolicy removes a policy line that matches the hashed policyKey.
func (a *adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	key := policyKey(ptype, rule)

	return a.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(a.bucket)
		return bucket.Delete([]byte(key))
	})
}

func (a *adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	for _, r := range rules {
		return a.RemovePolicy(sec, ptype, r)
	}
	return nil
}

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

func (a *adapter) putLine(bucket *bolt.Bucket, ptype string, line []string) error {
	pLine := savePolicyLine(ptype, line)

	key := []byte(pLine.Key)

	bts, err := json.Marshal(pLine)
	if err != nil {
		return err
	}

	return bucket.Put(key, bts)
}

// RemoveFilteredPolicy is not implemented. It does not make sense performance-wise as we must scan the whole bucket.
func (a *adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return errors.New("not implemented")
}
