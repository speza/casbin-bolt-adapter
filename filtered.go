package boltadapter

import (
	"bytes"
	"fmt"
	bolt "github.com/coreos/bbolt"
)

// RemoveFilteredPolicy filters based on the prefix.
func (a *adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
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
			return bucket.Delete(k)
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
