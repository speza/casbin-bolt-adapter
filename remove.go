package boltadapter

import bolt "github.com/coreos/bbolt"

// RemovePolicy removes a policy line that matches key.
func (a *adapter) RemovePolicy(sec string, ptype string, line []string) error {
	return a.db.Update(func(tx *bolt.Tx) error {
		rule := convertRule(ptype, line)
		bucket := tx.Bucket(a.bucket)
		return bucket.Delete([]byte(rule.Key))
	})
}

// RemovePolicies removes multiple policies.
func (a *adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
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
