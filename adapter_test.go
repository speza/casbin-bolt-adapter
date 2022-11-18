package boltadapter

import (
	"os"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	bolt "go.etcd.io/bbolt"
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

	a, err := NewAdapter(db, "casbin")
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
	_ = os.Remove(testDB)
}

func Test_AdapterTest_Suite(t *testing.T) {
	suite.Run(t, new(AdapterTestSuite))
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
	testGetPolicy(t, e, [][]string{{"roger", "data1", "write"}})

	e.RemovePolicy("roger", "data1", "write")
	testGetPolicy(t, e, [][]string{})

	e.AddPolicies([][]string{{"roger", "data1", "read"}, {"roger", "data1", "write"}})
	testGetPolicy(t, e, [][]string{{"roger", "data1", "read"}, {"roger", "data1", "write"}})

	e.RemoveFilteredPolicy(0, "roger")
	testGetPolicy(t, e, [][]string{})

	_, err := e.RemoveFilteredPolicy(1, "data1")
	assert.EqualError(t, err, "fieldIndex != 0: adapter only supports filter by prefix")

	e.AddPolicies([][]string{{"roger", "data1", "read"}, {"roger", "data1", "write"}})
	testGetPolicy(t, e, [][]string{{"roger", "data1", "read"}, {"roger", "data1", "write"}})

	e.RemovePolicies([][]string{{"roger", "data1", "read"}, {"roger", "data1", "write"}})
	testGetPolicy(t, e, [][]string{})
}

func (suite *AdapterTestSuite) Test_UpdatePolicy() {
	e := suite.enforcer
	t := suite.T()

	ok, err := e.AddPolicies([][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
	assert.NoError(t, err)
	assert.True(t, ok)

	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	ok, err = e.UpdatePolicy([]string{"alice", "data1", "read"}, []string{"alice", "data3", "read"})
	assert.NoError(t, err)
	assert.True(t, ok)

	testGetPolicy(t, e, [][]string{{"alice", "data3", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func (suite *AdapterTestSuite) Test_UpdatePolices() {
	e := suite.enforcer
	t := suite.T()

	ok, err := e.AddPolicies([][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
	assert.NoError(t, err)
	assert.True(t, ok)

	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	ok, err = e.UpdatePolicies([][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}}, [][]string{{"alice", "data3", "read"}, {"bob", "data3", "write"}})
	assert.NoError(t, err)
	assert.True(t, ok)

	testGetPolicy(t, e, [][]string{{"alice", "data3", "read"}, {"bob", "data3", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func (suite *AdapterTestSuite) Test_UpdateFilteredPolicies() {
	e := suite.enforcer
	t := suite.T()

	ok, err := e.AddPolicies([][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
	assert.NoError(t, err)
	assert.True(t, ok)

	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	_, err = e.UpdateFilteredPolicies([][]string{{"alice", "data3", "read"}}, 0, "alice", "data1")
	assert.NoError(t, err)

	testGetPolicy(t, e, [][]string{{"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"alice", "data3", "read"}})
}
