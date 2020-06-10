#### WIP: Casbin BoltDB Adapter

[![speza](https://circleci.com/gh/speza/casbin-bolt-adapter.svg?style=svg)](https://app.circleci.com/pipelines/github/speza/casbin-bolt-adapter)

A simple Casbin BoltDB Adapter (see https://casbin.org/docs/en/adapters).
This flavour supports the **auto-save** functionality.

This is currently still being worked on. Right now it supports the autosave functionality, but I'm currently looking to 
work in filtered adapter functionality - difficult with a simple k/v store like Bolt!

Individual policy lines get saved into the specified BoltDB bucket which is keyed using a `::` delimited value of the
role. The value content is a JSON representation of the policy rule.
