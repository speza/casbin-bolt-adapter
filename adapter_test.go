package boltadapter

import (
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"
	bolt "github.com/coreos/bbolt"
	"os"
	"testing"
)

const tmpDat = "test.dat"

func TestAdapter_AddRemovePolicy(t *testing.T) {
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

	adapter, err := NewAdapter(db, "casbin")
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

	testGetPolicy(t, enforcer.GetPolicy(), [][]string{{"role-a", "data1", "write"}, {"role-b", "data2", "read"}})
	testGetPolicy(t, enforcer.GetNamedGroupingPolicy("g"), [][]string{{"user-a", "role-a"}, {"user-b", "role-b"}})

	enforcer.RemovePolicy("user-b", "data2", "read")

	testGetPolicy(t, enforcer.GetPolicy(), [][]string{{"role-a", "data1", "write"}, {"role-b", "data2", "read"}})

	enforcer.DeleteRoleForUser("user-b", "role-b")

	testGetPolicy(t, enforcer.GetNamedGroupingPolicy("g"), [][]string{{"user-a", "role-a"}})
}

func TestAdapter_SavePolicy(t *testing.T) {
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

	adapter, err := NewAdapter(db, "casbin")
	if err != nil {
		t.Fatalf("error creating adapter: %s\n", err.Error())
	}

	enforcer, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	if err != nil {
		t.Fatalf("error creating enforcer: %s\n", err.Error())
	}

	enforcer.EnableAutoSave(false)

	enforcer.AddPolicy("role-a", "data1", "write")
	enforcer.AddPolicy("role-b", "data2", "read")
	enforcer.AddRoleForUser("user-a", "role-a")
	enforcer.AddRoleForUser("user-b", "role-b")

	enforcer.SavePolicy()

	testGetPolicy(t, enforcer.GetPolicy(), [][]string{{"role-a", "data1", "write"}, {"role-b", "data2", "read"}})
	testGetPolicy(t, enforcer.GetNamedGroupingPolicy("g"), [][]string{{"user-a", "role-a"}, {"user-b", "role-b"}})
}

func testGetPolicy(t *testing.T, got [][]string, wanted [][]string) {
	t.Helper()

	if !util.Array2DEquals(wanted, got) {
		t.Errorf("test get policy failed: got: %v wanted %v", got, wanted)
		return
	}
}
