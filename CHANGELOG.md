# v2.1.0 (2022-05-18)

Changes:

- When stdin is not a tty, do not show a prompt; just read the master password
  from stdin directly. This mode of operation is useful when calling pwget from
  a script or other automated process.
- Add go.mod file to work with newer Go versions.
- Update all dependencies.

# v2.0 (2017-12-26)

**Backwards-incompatible changes:**

- Passwords are encoded in Base-85 (Z85) instead of Base-16 (hexadecimal).
  This increases entropy density, and ensures that more diverse character sets
  (i.e. uppercase letters and symbols) are used, as required by some websites.
  However, this means that entirely different password strings are generated.

Changes:

- Rename binary from `pwget` to `pwget2` to allow parallel installation with
  1.x version (for transitioning passwords one after one).
- Windows is now a supported target platform.
- Add optional length argument that truncates passwords to comply with maximum
  password length requirements of stupid services.

# v1.2 (2017-06-08)

Bugfixes:

- Fix display of prompt when stdout is piped.

# v1.1 (2017-06-07)

Changes:

- Remove openssl-1.0 dependency.

# v1.0 (2016-03-20)

Initial release.
