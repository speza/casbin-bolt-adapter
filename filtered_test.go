package boltadapter

import (
	bolt "github.com/coreos/bbolt"
	"os"
	"testing"
)

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
