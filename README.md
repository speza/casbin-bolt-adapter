#### Fork of [this](https://github.com/speza/casbin-bolt-adapter)

#### Casbin BoltDB Adapter (Experimental)

I have marked this as experimental because I haven't put an awful amount of time into it. It needs more use to confirm its suitable for others needs.

[![speza](https://circleci.com/gh/speza/casbin-bolt-adapter.svg?style=svg)](https://app.circleci.com/pipelines/github/speza/casbin-bolt-adapter)

A simple Casbin BoltDB Adapter (see https://casbin.org/docs/en/adapters).
This flavour supports the **auto-save** functionality.

Right now it supports the autosave functionality, and I've worked in some restricted filtered adapter functionality - difficult with a simple k/v store like Bolt.

Individual policy lines get saved into the specified BoltDB bucket which is keyed using a `::` delimited value of the
role. The value content is a JSON representation of the policy rule.
