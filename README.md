#### WIP: Casbin BoltDB Adapter
A simple Casbin BoltDB Adapter (see https://casbin.org/docs/en/adapters).
This flavour supports the **auto-save** functionality.

Individual policy lines get saved into a BoltDB bucket which is keyed using a meow hash of the policy line.
The byte content is a JSON representation of the policy line.
