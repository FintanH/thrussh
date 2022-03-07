# Thrussh

## Soft Fork

**NOTE**: This is a soft fork of the original
[`thrussh`](//nest.pijul.com/pijul/thrussh). The motivation for this
fork was to be able to publish changes that the
[`radicle-link`](https://github.com/radicle-dev/radicle-link/) family
of packages relies on. Patches were made upstream, but have not landed
in `thrussh` proper.

We **do not** recommned relying on this package for any long-term use.

## Description

A full implementation of the SSH 2 protocol, both server-side and client-side.

Thrussh is completely asynchronous, and can be combined with other protocols using [Tokio](//tokio.rs).
