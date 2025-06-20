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

When creating an instance of this store, you specify whether you
want to use a "backing file" to store credentials between runs
(or to make them available from multiple applications). If you
don't specify a backing file, this is an in-memory store only,
and the credentials vanish when your application terminates.

Do not mistake the "backing file" for an update-to-date copy
of your in-memory credentials! The in-memory credentials are
only saved to the backing file when explicitly requested
or when the store is destroyed (that is,
the last reference to it is released). And the backing file
is only read when the store is first created, so to read
a backing file you have to create a new store.

# Ambiguity

This store supports ambiguity, that is, the ability to create
multiple credentials associated with the same service name
and username. If you specify the `target` modifier when
creating an entry, a new credential with an empty password
will be created immediately
for the specified service name and username,
and this newly created credential may or may not
be _ambiguous_ (that is, an additional credential
associated with the same service name and username):

* If there was _not_ an existing credential for your service name
  and username, then the newly-created credential will be the
  only one, so the returned entry will be a specifier
  (as well as a wrapper) for that credential.
* If there _was_ an existing credential for your service name and username,
  then the newly-created credential is ambiguous, so
  the returned entry will _not_ be a specifier,
  but it will wrap the newly-created (ambiguous) credential
  so it can be used to set and read its password.

In all cases, the use of the `target` modifier will cause
the created credential to have two additional attributes:

* *creation_date*, an HTTP-style date showing when the
  credential was created. This cannot be updated, nor
  can it be added to credentials that don't have it.
* *comment*, the string value of the `target` modifier.
  This can be updated, and it can be added to credentials
  that don't have it.

# Attributes

Credentials in the sample store don't have attributes other than those
described in the section on Ambiguity above.

 */

pub mod credential;
pub mod store;
#[cfg(test)]
mod test;
