/*!

# Sample credential store implementation

This is an incredibly simple store that uses a file for persistence.
It is provided for a few reasons:

- It supports testing of the keyring-core code.
- It provides a cross-platform reference store that clients can test against.
  (For this purpose, it exposes its internal structures publicly, so they
  can be explored in a debugger.)
- It provides a sample whose structure can be used as a
  template for building other credential stores.

This store is not warranted to support real-world applications. It's neither
secure nor robust. Every platform provides better stores than this;
use them instead.

 */

pub mod credential;
pub mod store;
#[cfg(test)]
mod test;
