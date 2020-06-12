package boltadapter

import (
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"
	bolt "github.com/coreos/bbolt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"io/ioutil"
	"os"
	"testing"
)

const testDB = "test.db"

type AdapterTestSuite struct {
	suite.Suite
	db       *bolt.DB
	enforcer casbin.IEnforcer
}

func testGetPolicy(t *testing.T, e casbin.IEnforcer, wanted [][]string) {
	t.Helper()
	got := e.GetPolicy()
	if !util.Array2DEquals(wanted, got) {
		t.Error("got policy: ", got, ", wanted policy: ", wanted)
	}
}

func (suite *AdapterTestSuite) SetupTest() {
	t := suite.T()

	db, err := bolt.Open(testDB, 0600, nil)
	if err != nil {
		t.Fatalf("error opening bolt db: %s\n", err.Error())
	}
	suite.db = db

	bts, err := ioutil.ReadFile("examples/rbac_policy.csv")
	if err != nil {
		t.Error(err)
	}

	a, err := NewAdapter(db, "casbin", string(bts))
	if err != nil {
		t.Error(err)
	}

	enforcer, err := casbin.NewEnforcer("examples/rbac_model.conf", a)
	if err != nil {
		t.Errorf("error creating enforcer: %s\n", err.Error())
	}

	suite.enforcer = enforcer
}

func (suite *AdapterTestSuite) TearDownTest() {
	suite.db.Close()
	if _, err := os.Stat(testDB); err == nil {
		os.Remove(testDB)
	}
}

func Test_AdapterTest_Suite(t *testing.T) {
	suite.Run(t, new(AdapterTestSuite))
}

func (suite *AdapterTestSuite) Test_LoadBuiltinPolicy() {
	testGetPolicy(suite.T(), suite.enforcer, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func (suite *AdapterTestSuite) Test_SavePolicy_ReturnsErr() {
	e := suite.enforcer
	t := suite.T()

	err := e.SavePolicy()
	assert.EqualError(t, err, "not supported: must use auto-save with this adapter")
}

func (suite *AdapterTestSuite) Test_AutoSavePolicy() {
	e := suite.enforcer
	t := suite.T()

	e.EnableAutoSave(true)

	e.AddPolicy("roger", "data1", "write")
	e.LoadPolicy()
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"roger", "data1", "write"}})

	e.RemovePolicy("roger", "data1", "write")
	e.LoadPolicy()
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	e.AddPolicies([][]string{{"roger", "data1", "read"}, {"roger", "data1", "write"}})
	e.LoadPolicy()
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"roger", "data1", "read"}, {"roger", "data1", "write"}})

	e.RemoveFilteredPolicy(0, "roger")
	e.LoadPolicy()
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	_, err := e.RemoveFilteredPolicy(1, "data1")
	assert.EqualError(t, err, "fieldIndex != 0: adapter only supports filter by prefix")

	e.AddPolicies([][]string{{"roger", "data1", "read"}, {"roger", "data1", "write"}})
	e.LoadPolicy()
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"roger", "data1", "read"}, {"roger", "data1", "write"}})

	e.RemovePolicies([][]string{{"roger", "data1", "read"}, {"roger", "data1", "write"}})
	e.LoadPolicy()
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

}

//
// func TestAdapter_SavePolicy(t *testing.T) {
// 	db, err := bolt.Open(testDB, 0600, nil)
// 	if err != nil {
// 		t.Fatalf("error opening bolt db: %s\n", err.Error())
// 	}
// 	defer func() {
// 		db.Close()
// 		if _, err := os.Stat(testDB); err == nil {
// 			os.Remove(testDB)
// 		}
// 	}()
//
// 	enforcer := initEnforcer(t, db)
//
// 	enforcer.EnableAutoSave(false)
//
// 	enforcer.AddPolicy("role-a", "data1", "write")
// 	enforcer.AddPolicy("role-b", "data2", "read")
// 	enforcer.AddRoleForUser("user-a", "role-a")
// 	enforcer.AddRoleForUser("user-b", "role-b")
//
// 	enforcer.SavePolicy()
// 	enforcer.LoadPolicy()
//
// 	testGetPolicy(t, enforcer.GetPolicy(), [][]string{{"role-a", "data1", "write"}, {"role-b", "data2", "read"}})
// 	testGetPolicy(t, enforcer.GetNamedGroupingPolicy("g"), [][]string{{"user-a", "role-a"}, {"user-b", "role-b"}})
// }
//
// func TestAdapter_AddPolicy(t *testing.T) {
// 	db, err := bolt.Open(testDB, 0600, nil)
// 	if err != nil {
// 		t.Fatalf("error opening bolt db: %s\n", err.Error())
// 	}
// 	defer func() {
// 		db.Close()
// 		if _, err := os.Stat(testDB); err == nil {
// 			os.Remove(testDB)
// 		}
// 	}()
//
// 	enforcer := initEnforcer(t, db)
//
// 	enforcer.AddPolicy("role-a", "data1", "write")
// 	enforcer.AddPolicy("role-b", "data2", "read")
// 	enforcer.AddRoleForUser("user-a", "role-a")
// 	enforcer.AddRoleForUser("user-b", "role-b")
//
// 	enforcer.LoadPolicy()
//
// 	testGetPolicy(t, enforcer.GetPolicy(), [][]string{{"role-a", "data1", "write"}, {"role-b", "data2", "read"}})
// 	testGetPolicy(t, enforcer.GetNamedGroupingPolicy("g"), [][]string{{"user-a", "role-a"}, {"user-b", "role-b"}})
// }
//
// func TestAdapter_AddPolicies(t *testing.T) {
// 	db, err := bolt.Open(testDB, 0600, nil)
// 	if err != nil {
// 		t.Fatalf("error opening bolt db: %s\n", err.Error())
// 	}
// 	defer func() {
// 		db.Close()
// 		if _, err := os.Stat(testDB); err == nil {
// 			os.Remove(testDB)
// 		}
// 	}()
//
// 	enforcer := initEnforcer(t, db)
//
// 	enforcer.AddPolicies([][]string{{"role-a", "data1", "write"}, {"role-b", "data2", "read"}})
//
// 	enforcer.LoadPolicy()
//
// 	testGetPolicy(t, enforcer.GetPolicy(), [][]string{{"role-a", "data1", "write"}, {"role-b", "data2", "read"}})
// }
//
// func TestAdapter_RemoveFilteredPolicy_Index0FieldValue1(t *testing.T) {
// 	db, err := bolt.Open(testDB, 0600, nil)
// 	if err != nil {
// 		t.Fatalf("error opening bolt db: %s\n", err.Error())
// 	}
// 	defer func() {
// 		db.Close()
// 		if _, err := os.Stat(testDB); err == nil {
// 			os.Remove(testDB)
// 		}
// 	}()
//
// 	enforcer := initEnforcer(t, db)
//
// 	enforcer.AddPolicy("subject-a", "data1", "get")
// 	enforcer.AddPolicy("subject-a", "data1", "write")
// 	enforcer.AddPolicy("subject-a", "data1", "delete")
// 	enforcer.AddPolicy("subject-b", "data1", "get")
// 	enforcer.AddPolicy("subject-b", "data1", "write")
// 	enforcer.AddPolicy("subject-b", "data1", "delete")
//
// 	enforcer.RemoveFilteredPolicy(0, "subject-a")
//
// 	enforcer.LoadPolicy()
//
// 	testGetPolicy(t, enforcer.GetPolicy(), [][]string{{"subject-b", "data1", "delete"}, {"subject-b", "data1", "get"}, {"subject-b", "data1", "write"}})
// }
//
// func TestAdapter_RemoveFilteredPolicy_Index0FieldValue2(t *testing.T) {
// 	db, err := bolt.Open(testDB, 0600, nil)
// 	if err != nil {
// 		t.Fatalf("error opening bolt db: %s\n", err.Error())
// 	}
// 	defer func() {
// 		db.Close()
// 		if _, err := os.Stat(testDB); err == nil {
// 			os.Remove(testDB)
// 		}
// 	}()
//
// 	enforcer := initEnforcer(t, db)
//
// 	enforcer.AddPolicy("subject-a", "data1", "get")
// 	enforcer.AddPolicy("subject-a", "data1", "write")
// 	enforcer.AddPolicy("subject-b", "data1", "get")
// 	enforcer.AddPolicy("subject-b", "data1", "write")
// 	enforcer.AddPolicy("subject-b", "data2", "delete")
//
// 	enforcer.RemoveFilteredPolicy(0, "subject-b", "data1")
//
// 	enforcer.LoadPolicy()
//
// 	testGetPolicy(t, enforcer.GetPolicy(), [][]string{{"subject-a", "data1", "get"}, {"subject-a", "data1", "write"}, {"subject-b", "data2", "delete"}})
// }
//
// func TestAdapter_RemoveFilteredPolicy_IndexGreaterThan0_Errors(t *testing.T) {
// 	db, err := bolt.Open(testDB, 0600, nil)
// 	if err != nil {
// 		t.Fatalf("error opening bolt db: %s\n", err.Error())
// 	}
// 	defer func() {
// 		db.Close()
// 		if _, err := os.Stat(testDB); err == nil {
// 			os.Remove(testDB)
// 		}
// 	}()
//
// 	enforcer := initEnforcer(t, db)
//
// 	enforcer.AddPolicy("subject-a", "subject-a", "get")
//
// 	if _, err := enforcer.RemoveFilteredPolicy(1, "subject-a"); err == nil {
// 		t.Fatalf("should have got index err")
// 	}
// }
//
// func TestAdapter_RemovePolicy(t *testing.T) {
// 	db, err := bolt.Open(testDB, 0600, nil)
// 	if err != nil {
// 		t.Fatalf("error opening bolt db: %s\n", err.Error())
// 	}
// 	defer func() {
// 		db.Close()
// 		if _, err := os.Stat(testDB); err == nil {
// 			os.Remove(testDB)
// 		}
// 	}()
//
// 	adapter, err := NewAdapter(db, "casbin", "")
// 	if err != nil {
// 		t.Fatalf("error creating adapter: %s\n", err.Error())
// 	}
//
// 	enforcer, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
// 	if err != nil {
// 		t.Fatalf("error creating enforcer: %s\n", err.Error())
// 	}
//
// 	enforcer.AddPolicy("role-a", "data1", "write")
// 	enforcer.AddPolicy("role-b", "data2", "read")
// 	enforcer.AddRoleForUser("user-a", "role-a")
// 	enforcer.AddRoleForUser("user-b", "role-b")
//
// 	enforcer.RemovePolicy("user-b", "data2", "read")
// 	enforcer.DeleteRoleForUser("user-b", "role-b")
//
// 	enforcer.LoadPolicy()
//
// 	testGetPolicy(t, enforcer.GetPolicy(), [][]string{{"role-a", "data1", "write"}, {"role-b", "data2", "read"}})
// 	testGetPolicy(t, enforcer.GetNamedGroupingPolicy("g"), [][]string{{"user-a", "role-a"}})
// }
//
// func TestAdapter_RemovePolicies(t *testing.T) {
// 	db, err := bolt.Open(testDB, 0600, nil)
// 	if err != nil {
// 		t.Fatalf("error opening bolt db: %s\n", err.Error())
// 	}
// 	defer func() {
// 		db.Close()
// 		if _, err := os.Stat(testDB); err == nil {
// 			os.Remove(testDB)
// 		}
// 	}()
//
// 	enforcer := initEnforcer(t, db)
//
// 	enforcer.AddPolicy("role-a", "data1", "write")
// 	enforcer.AddPolicy("role-b", "data2", "read")
//
// 	enforcer.RemovePolicies([][]string{{"role-a", "data1", "write"}, {"role-b", "data2", "read"}})
//
// 	enforcer.LoadPolicy()
//
// 	testGetPolicy(t, enforcer.GetPolicy(), [][]string{})
// }
