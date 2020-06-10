package main

import (
	"fmt"
	bolt "github.com/coreos/bbolt"
	boltadapter "github.com/speza/casbin-bolt-adapter"
	"log"
)

func main() {
	db, _ := bolt.Open("testing.dat", 0600, nil)

	_ = db.Update(func(tx *bolt.Tx) error {
		bucket, _ := tx.CreateBucketIfNotExists([]byte("bucket"))

		bucket.Put([]byte("p::role-a::action-a::get"), []byte(""))
		bucket.Put([]byte("p::role-a::action-a::write"), []byte(""))

		bucket.Put([]byte("p::role-b::action-b::get"), []byte(""))
		bucket.Put([]byte("p::role-b::action-b::write"), []byte(""))

		bucket.Put([]byte("p::role-c::action-a::get"), []byte(""))
		bucket.Put([]byte("p::role-c::action-a::write"), []byte(""))

		bucket.Put([]byte("p::role-d::action-b::get"), []byte(""))
		bucket.Put([]byte("p::role-d::action-b::write"), []byte(""))

		return nil
	})

	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("bucket"))

		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			fmt.Printf("key=%s, value=%s\n", k, v)
		}

		return nil
	})

	adapter, err := boltadapter.NewAdapter(db, "bucket", "")
	if err != nil {
		log.Fatal(err)
	}
	adapter.RemoveFilteredPolicy("", "p", 0, "role-d", "action")

	fmt.Println("-----")

	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("bucket"))

		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			fmt.Printf("key=%s, value=%s\n", k, v)
		}

		return nil
	})

	err = adapter.RemoveFilteredPolicy("", "p", 1, "action")
	fmt.Println(err)
}
