package boltadapter

import (
	"encoding/json"
	bolt "github.com/coreos/bbolt"
)

// AddPolicy inserts or updates an existing policy.
func (a *adapter) AddPolicy(sec string, ptype string, rule []string) error {
	return a.db.Update(func(tx *bolt.Tx) error {
		line := convertRule(ptype, rule)
		bucket := tx.Bucket(a.bucket)

		bts, err := json.Marshal(line)
		if err != nil {
			return err
		}

		return bucket.Put([]byte(line.Key), bts)
	})
}

// AddPolicies inserts multiple policies.
func (a *adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	return a.db.Update(func(tx *bolt.Tx) error {
		for _, r := range rules {
			line := convertRule(ptype, r)
			bucket := tx.Bucket(a.bucket)

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
