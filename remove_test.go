package boltadapter

import (
	"github.com/casbin/casbin/v2"
	bolt "github.com/coreos/bbolt"
	"os"
	"testing"
)

func TestAdapter_RemovePolicy(t *testing.T) {
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

	adapter, err := NewAdapter(db, "casbin", "")
	if err != nil {
		t.Fatalf("error creating adapter: %s\n", err.Error())
	}

	enforcer, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	if err != nil {
		t.Fatalf("error creating enforcer: %s\n", err.Error())
	}

	enforcer.AddPolicy("role-a", "data1", "write")
	enforcer.AddPolicy("role-b", "data2", "read")
	enforcer.AddRoleForUser("user-a", "role-a")
	enforcer.AddRoleForUser("user-b", "role-b")

	enforcer.RemovePolicy("user-b", "data2", "read")
	enforcer.DeleteRoleForUser("user-b", "role-b")

	enforcer.LoadPolicy()

	testGetPolicy(t, enforcer.GetPolicy(), [][]string{{"role-a", "data1", "write"}, {"role-b", "data2", "read"}})
	testGetPolicy(t, enforcer.GetNamedGroupingPolicy("g"), [][]string{{"user-a", "role-a"}})
}

func TestAdapter_RemovePolicies(t *testing.T) {
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

	enforcer.RemovePolicies([][]string{{"role-a", "data1", "write"}, {"role-b", "data2", "read"}})

	enforcer.LoadPolicy()

	testGetPolicy(t, enforcer.GetPolicy(), [][]string{})
}
