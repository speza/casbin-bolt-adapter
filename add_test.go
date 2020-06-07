package boltadapter

import (
	bolt "github.com/coreos/bbolt"
	"os"
	"testing"
)

func TestAdapter_AddPolicy(t *testing.T) {
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
	enforcer.AddRoleForUser("user-a", "role-a")
	enforcer.AddRoleForUser("user-b", "role-b")

	enforcer.LoadPolicy()

	testGetPolicy(t, enforcer.GetPolicy(), [][]string{{"role-a", "data1", "write"}, {"role-b", "data2", "read"}})
	testGetPolicy(t, enforcer.GetNamedGroupingPolicy("g"), [][]string{{"user-a", "role-a"}, {"user-b", "role-b"}})
}

func TestAdapter_AddPolicies(t *testing.T) {
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

	enforcer.AddPolicies([][]string{{"role-a", "data1", "write"}, {"role-b", "data2", "read"}})

	enforcer.LoadPolicy()

	testGetPolicy(t, enforcer.GetPolicy(), [][]string{{"role-a", "data1", "write"}, {"role-b", "data2", "read"}})
}
