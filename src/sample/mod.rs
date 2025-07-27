/*!

# Sample Credential Store

This sample store is provided for two purposes:

- It provides a cross-platform way to test your client code during development.
  (To help with this, all of its internal structures are public.)
- It provides a template for developers who want to write credential stores.
  (The tests as well as the source structure can be adapted.)

This store is explicitly *not* for use in production apps! It's neither robust
nor secure.

# Persistence

When creating an instance of this store, you specify whether you want to use a
"backing file" to store credentials between runs (or to make them available to
other applications). If you don't specify a backing file, this is an in-memory
store only, and the credentials vanish when your application terminates.

The "backing file" is _not_ kept up to date as credentials are created, deleted,
or modified! The in-memory credentials are only saved to the backing file when
explicitly requested or when a store is destroyed (that is, the last reference
to it is released). The backing file is only read when a store is first created.
(To read a backing file, you have to create a new store.)

# Ambiguity

This store supports ambiguity, that is, the ability to create
multiple credentials associated with the same service name
and username. If you specify the `target` modifier when
creating an entry, a new credential with an empty password
will be created immediately for the specified service name and username.

* If there was _not_ an existing credential for your service name
  and username, then the newly-created credential will be the
  only one, so the returned entry will not be ambiguous.
* If there _was_ an existing credential for your service name and username,
  then the returned entry will be ambiguous.

In all cases, the use of the `target` modifier will cause
the created credential to have two additional attributes:

* *creation_date*, an HTTP-style date showing when the
  credential was created. This cannot be updated, nor
  can it be added to credentials that don't have it.
* *comment*, the string value of the `target` modifier.
  This can be updated, and it can be added to credentials
  that don't have it.

# Attributes

Credentials in this store, in addition to the attributes
described in the section on Ambiguity above, have
a single read-only attribute `uuid` which is the
unique ID of the credential in the store.

# Search

This store implements credential search. Specs can specify
desired regular expressions for the `service` and `user` a
credential is attached to, and for the `comment` and `uuid` attributes
of the credential itself. (All other key/value pairs in the spec
are ignored.) Credentials are returned only if _all_ the
specified regular expressions match against its values.

Note: Search is implemented by iterating over every credential
in the store. This is an in-memory store, so it happens
pretty quickly.

 */

pub mod credential;
pub mod store;
#[cfg(test)]
mod test;
