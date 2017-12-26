# v2.0 (TBD)

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
