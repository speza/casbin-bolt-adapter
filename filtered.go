package boltadapter

import (
	"bytes"
	"errors"
	"fmt"
	bolt "github.com/coreos/bbolt"
)

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
func (a *adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
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
