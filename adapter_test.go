package boltadapter

import (
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"
	bolt "github.com/coreos/bbolt"
	"os"
	"testing"
)

const tmpDat = "test.dat"

const builtinPolicy = `p, role-a, data1, write
p, role-b, data2, read`

func testGetPolicy(t *testing.T, got [][]string, wanted [][]string) {
	t.Helper()

	if !util.Array2DEquals(wanted, got) {
		t.Errorf("test get policy failed: got: %v wanted %v", got, wanted)
		return
	}
}

func initEnforcer(t *testing.T, db *bolt.DB) *casbin.Enforcer {
	adapter, err := NewAdapter(db, "casbin", "")
	if err != nil {
		t.Fatalf("error creating adapter: %s\n", err.Error())
	}

	enforcer, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	if err != nil {
		t.Fatalf("error creating enforcer: %s\n", err.Error())
	}
	return enforcer
}

func TestAdapter_LoadBuiltinPolicy(t *testing.T) {
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

	adapter, err := NewAdapter(db, "casbin", builtinPolicy)
	if err != nil {
		t.Fatalf("error creating adapter: %s\n", err.Error())
	}

	enforcer, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	if err != nil {
		t.Fatalf("error creating enforcer: %s\n", err.Error())
	}

	testGetPolicy(t, enforcer.GetPolicy(), [][]string{{"role-a", "data1", "write"}, {"role-b", "data2", "read"}})
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

	enforcer := initEnforcer(t, db)

	enforcer.EnableAutoSave(false)

	enforcer.AddPolicy("role-a", "data1", "write")
	enforcer.AddPolicy("role-b", "data2", "read")
	enforcer.AddRoleForUser("user-a", "role-a")
	enforcer.AddRoleForUser("user-b", "role-b")

	enforcer.SavePolicy()
	enforcer.LoadPolicy()

	testGetPolicy(t, enforcer.GetPolicy(), [][]string{{"role-a", "data1", "write"}, {"role-b", "data2", "read"}})
	testGetPolicy(t, enforcer.GetNamedGroupingPolicy("g"), [][]string{{"user-a", "role-a"}, {"user-b", "role-b"}})
}

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

func TestAdapter_RemoveFilteredPolicy_Index0FieldValue1(t *testing.T) {
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

	enforcer.AddPolicy("subject-a", "data1", "get")
	enforcer.AddPolicy("subject-a", "data1", "write")
	enforcer.AddPolicy("subject-a", "data1", "delete")
	enforcer.AddPolicy("subject-b", "data1", "get")
	enforcer.AddPolicy("subject-b", "data1", "write")
	enforcer.AddPolicy("subject-b", "data1", "delete")

	enforcer.RemoveFilteredPolicy(0, "subject-a")

	enforcer.LoadPolicy()

	testGetPolicy(t, enforcer.GetPolicy(), [][]string{{"subject-b", "data1", "delete"}, {"subject-b", "data1", "get"}, {"subject-b", "data1", "write"}})
}

func TestAdapter_RemoveFilteredPolicy_Index0FieldValue2(t *testing.T) {
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

	enforcer.AddPolicy("subject-a", "data1", "get")
	enforcer.AddPolicy("subject-a", "data1", "write")
	enforcer.AddPolicy("subject-b", "data1", "get")
	enforcer.AddPolicy("subject-b", "data1", "write")
	enforcer.AddPolicy("subject-b", "data2", "delete")

	enforcer.RemoveFilteredPolicy(0, "subject-b", "data1")

	enforcer.LoadPolicy()

	testGetPolicy(t, enforcer.GetPolicy(), [][]string{{"subject-a", "data1", "get"}, {"subject-a", "data1", "write"}, {"subject-b", "data2", "delete"}})
}

func TestAdapter_RemoveFilteredPolicy_IndexGreaterThan0_Errors(t *testing.T) {
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

	enforcer.AddPolicy("subject-a", "subject-a", "get")

	if _, err := enforcer.RemoveFilteredPolicy(1, "subject-a"); err == nil {
		t.Fatalf("should have got index err")
	}
}

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
