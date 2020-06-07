package boltadapter

import (
	bolt "github.com/coreos/bbolt"
	"os"
	"testing"
)

func TestAdapter_RemoveFilteredPolicy(t *testing.T) {
	db, err := bolt.Open(tmpDat, 0600, nil)
	if err != nil {
		t.Fatalf("error opening bolt db: %s\n", err.Error())
	}
	defer func() {
		db.Close()
		if _, err := os.Stat(tmpDat); err == nil {
			os.Remove(tmpDat)
		}
	}()

	enforcer := initEnforcer(t, db)

	enforcer.AddPolicy("role-a", "data1", "write")
	enforcer.AddPolicy("role-b", "data2", "read")
	enforcer.RemoveFilteredPolicy(0, "role-a")

	enforcer.LoadPolicy()

	testGetPolicy(t, enforcer.GetPolicy(), [][]string{{"role-b", "data2", "read"}})
}
