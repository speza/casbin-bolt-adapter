package boltadapter

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	bolt "go.etcd.io/bbolt"
)

var _ persist.Adapter = (*adapter)(nil)
var _ persist.UpdatableAdapter = (*adapter)(nil)

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

func (cr *CasbinRule) Rule() []string {
	return strings.Split(cr.Key, "::")[1:]
}

type adapter struct {
	db            *bolt.DB
	bucket        []byte
	builtinPolicy string
}

// NewAdapter creates a new adapter. It assumes that the Bolt DB is already open. A bucket name is required and
// represents the Bolt bucket to save the data into. like to save to. The builtinPolicy is a string representation
// of a Casbin csv policy definition. If left builtinPolicy will not be used.
func NewAdapter(db *bolt.DB, bucket string) (*adapter, error) {
	if bucket == "" {
		return nil, errors.New("must provide a bucket")
	}

	adapter := &adapter{
		db:     db,
		bucket: []byte(bucket),
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

// SavePolicy is not supported for this adapter. Auto-save should be used.
func (a *adapter) SavePolicy(model model.Model) error {
	return errors.New("not supported: must use auto-save with this adapter")
}

// AddPolicy inserts or updates a rule.
func (a *adapter) AddPolicy(_ string, ptype string, rule []string) error {
	return a.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(a.bucket)

		line := convertRule(ptype, rule)

		bts, err := json.Marshal(line)
		if err != nil {
			return err
		}

		return bucket.Put([]byte(line.Key), bts)
	})
}

// AddPolicies inserts or updates multiple rules by iterating over each one and inserting it into the bucket.
func (a *adapter) AddPolicies(_ string, ptype string, rules [][]string) error {
	return a.db.Update(func(tx *bolt.Tx) error {
		for _, r := range rules {
			bucket := tx.Bucket(a.bucket)

			line := convertRule(ptype, r)

			bts, err := json.Marshal(line)
			if err != nil {
				return err
			}

			if err := bucket.Put([]byte(line.Key), bts); err != nil {
				return err
			}
		}

		return nil
	})
}

// RemoveFilteredPolicy has an implementation that is slightly limited in that we can only find and remove elements
// using a policy line prefix.
//
// For example, if you have the following policy:
//     p, subject-a, action-a, get
//     p, subject-a, action-a, write
//     p, subject-b, action-a, get
//     p, subject-b, action-a, write
//
// The following would remove all subject-a rules:
//     enforcer.RemoveFilteredPolicy(0, "subject-a")
// The following would remove all subject-a rules that contain action-a:
//     enforcer.RemoveFilteredPolicy(0, "subject-a", "action-a")
//
// The following does not work and will return an error:
//     enforcer.RemoveFilteredPolicy(1, "action-a")
//
// This is because we use leverage Bolts seek and prefix to find an item by prefix.
// Once these keys are found we can iterate over and remove them.
// Each policy rule is stored as a row in Bolt: p::subject-a::action-a::get
func (a *adapter) RemoveFilteredPolicy(_ string, ptype string, fieldIndex int, fieldValues ...string) error {
	if fieldIndex != 0 {
		return errors.New("fieldIndex != 0: adapter only supports filter by prefix")
	}

	rule := CasbinRule{}

	rule.PType = ptype
	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		rule.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		rule.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		rule.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		rule.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		rule.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		rule.V5 = fieldValues[5-fieldIndex]
	}

	filterPrefix := a.buildFilter(rule)

	matched := [][]byte{}
	if err := a.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(a.bucket).Cursor()

		prefix := []byte(filterPrefix)
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			matched = append(matched, k)
		}

		return nil
	}); err != nil {
		return err
	}

	return a.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(a.bucket)
		for _, k := range matched {
			if err := bucket.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

func (a *adapter) buildFilter(rule CasbinRule) string {
	filter := rule.PType
	if rule.V0 != "" {
		filter = fmt.Sprintf("%s::%s", filter, rule.V0)
	}
	if rule.V1 != "" {
		filter = fmt.Sprintf("%s::%s", filter, rule.V1)
	}
	if rule.V2 != "" {
		filter = fmt.Sprintf("%s::%s", filter, rule.V2)
	}
	if rule.V3 != "" {
		filter = fmt.Sprintf("%s::%s", filter, rule.V3)
	}
	if rule.V4 != "" {
		filter = fmt.Sprintf("%s::%s", filter, rule.V4)
	}
	if rule.V5 != "" {
		filter = fmt.Sprintf("%s::%s", filter, rule.V5)
	}
	return filter
}

// RemovePolicy removes a policy line that matches key.
func (a *adapter) RemovePolicy(_ string, ptype string, line []string) error {
	return a.db.Update(func(tx *bolt.Tx) error {
		rule := convertRule(ptype, line)
		bucket := tx.Bucket(a.bucket)
		return bucket.Delete([]byte(rule.Key))
	})
}

// RemovePolicies removes multiple policies.
func (a *adapter) RemovePolicies(_ string, ptype string, rules [][]string) error {
	return a.db.Update(func(tx *bolt.Tx) error {
		for _, r := range rules {
			rule := convertRule(ptype, r)
			bucket := tx.Bucket(a.bucket)
			if err := bucket.Delete([]byte(rule.Key)); err != nil {
				return err
			}
		}
		return nil
	})
}

func (a *adapter) UpdatePolicy(_ string, ptype string, oldRule, newRule []string) error {
	return a.db.Update(func(tx *bolt.Tx) error {
		old := convertRule(ptype, oldRule)
		new := convertRule(ptype, newRule)
		bucket := tx.Bucket(a.bucket)

		if err := bucket.Delete([]byte(old.Key)); err != nil {
			return err
		}

		bts, err := json.Marshal(new)
		if err != nil {
			return err
		}

		if err := bucket.Put([]byte(new.Key), bts); err != nil {
			return err
		}

		return nil
	})
}

func (a *adapter) UpdatePolicies(_ string, ptype string, oldRules, newRules [][]string) error {

	return a.db.Update(func(tx *bolt.Tx) error {

		bucket := tx.Bucket(a.bucket)

		for _, r := range oldRules {
			old := convertRule(ptype, r)

			if err := bucket.Delete([]byte(old.Key)); err != nil {
				return err
			}
		}

		for _, r := range newRules {
			new := convertRule(ptype, r)

			bts, err := json.Marshal(new)
			if err != nil {
				return err
			}

			if err := bucket.Put([]byte(new.Key), bts); err != nil {
				return err
			}
		}

		return nil
	})
}

func (a *adapter) UpdateFilteredPolicies(_ string, ptype string, newPolicies [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {

	if fieldIndex != 0 {
		return nil, errors.New("fieldIndex != 0: adapter only supports filter by prefix")
	}

	rule := CasbinRule{}

	rule.PType = ptype
	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		rule.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		rule.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		rule.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		rule.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		rule.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		rule.V5 = fieldValues[5-fieldIndex]
	}

	filterPrefix := a.buildFilter(rule)

	fmt.Println(filterPrefix)

	matched := []CasbinRule{}
	if err := a.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(a.bucket).Cursor()

		prefix := []byte(filterPrefix)
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			r := CasbinRule{}
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			matched = append(matched, r)
		}

		return nil
	}); err != nil {
		return nil, err
	}

	err := a.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(a.bucket)
		for _, r := range matched {
			fmt.Println(r.Key)
			if err := bucket.Delete([]byte(r.Key)); err != nil {
				return err
			}
		}

		for _, r := range newPolicies {
			new := convertRule(ptype, r)

			bts, err := json.Marshal(new)
			if err != nil {
				return err
			}

			if err := bucket.Put([]byte(new.Key), bts); err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	oldRules := make([][]string, 0, len(matched))

	for _, r := range matched {
		oldRules = append(oldRules, r.Rule())
	}

	return oldRules, err
}

func loadPolicy(rule CasbinRule, model model.Model) {
	lineText := rule.PType

	if rule.V0 != "" {
		lineText += ", " + rule.V0
	}
	if rule.V1 != "" {
		lineText += ", " + rule.V1
	}
	if rule.V2 != "" {
		lineText += ", " + rule.V2
	}
	if rule.V3 != "" {
		lineText += ", " + rule.V3
	}
	if rule.V4 != "" {
		lineText += ", " + rule.V4
	}
	if rule.V5 != "" {
		lineText += ", " + rule.V5
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

func convertRule(ptype string, line []string) CasbinRule {
	rule := CasbinRule{PType: ptype}

	keySlice := []string{ptype}

	l := len(line)
	if l > 0 {
		rule.V0 = line[0]
		keySlice = append(keySlice, line[0])
	}
	if l > 1 {
		rule.V1 = line[1]
		keySlice = append(keySlice, line[1])
	}
	if l > 2 {
		rule.V2 = line[2]
		keySlice = append(keySlice, line[2])
	}
	if l > 3 {
		rule.V3 = line[3]
		keySlice = append(keySlice, line[3])
	}
	if l > 4 {
		rule.V4 = line[4]
		keySlice = append(keySlice, line[4])
	}
	if l > 5 {
		rule.V5 = line[5]
		keySlice = append(keySlice, line[5])
	}

	rule.Key = strings.Join(keySlice, "::")

	return rule
}
