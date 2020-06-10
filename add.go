package boltadapter

import (
	"encoding/json"
	bolt "github.com/coreos/bbolt"
)

// AddPolicy inserts or updates a rule.
func (a *adapter) AddPolicy(sec string, ptype string, rule []string) error {
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
func (a *adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
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
