# pwget

pwget is a *stateless password manager*, a tool that generates all your
passwords from a single master password. Its main difference from similar tools
is that it maintains a list of revoked passwords. You can revoke a password if
a service that you use has had their password database leaked, or if you just
like to change your passwords regularly.

Of course, one can argue that the revocation list makes pwget
not-stateless-anymore, but I still consider it mostly stateless because the
revocation list can always be recovered by starting from an empty list,
generating passwords, and revoking those that don't work until you get to the
first non-revoked password.

## Security considerations

**WARNING: I'm not a professional cryptographer.** I deny all responsibility if
you use this code and then lose your passwords or identity.

Having said that, I consider the main attack vector to be identity theft
through sniffing the master password, e.g. via a keylogger. That attack vector
exists for all password managers that use a master password.

But for a stateless password manager, a master password cannot easily be
changed, unless you are willing to change all passwords derived from it. I
don't see a practical difference, though: If your master password is
compromised, you should always assume all derived passwords compromised as
well, since the adversary has likely already obtained a copy of your password
store (if your password manager maintains one).

In the end, the same advice as always holds true: Know your threat model, and
carefully weigh security against utility.

## Installation

```bash
# option 1
make
sudo make install

# option 2
make
ln -s $PWD/build/pwget ~/bin # or wherever you put your tools
```

## Usage

To generate a password,

```bash
pwget $DOMAIN
```

where `$DOMAIN` identifies the service that you're trying to log on. It's your
job to come up with a consistent scheme for these `$DOMAIN` values. pwget does
not enforce anything. The following three, for example, will generate
completely different passwords:

```bash
pwget example.com
pwget www.example.com
pwget johndoe@example.com
```

To revoke a password,

```bash
pwget --revoke $DOMAIN
```

Then generate the next password with `pwget $DOMAIN`. The list of revoked
passwords is stored at `$HOME/.pwget-revocation`, which contains the SHA256
hash of every revoked password. pwget will always show a list of all revoked
passwords that it encounters, so you can recover from an undesired revocation
easily.

### Maximum length restriction

Some stupid services enforce a maximum length of passwords. You should stop
using these services, but if you absolutely cannot, you can pass the maximum
password length as a second argument to truncate the generated password:

```bash
# stupidbank.com rejects passwords longer than 20 chars
pwget stupidbank.com 20
```

## Algorithm

In pseudo-code:

```
func getPassword(masterPassword, domain) {
    for iteration in 0..infinity {
        salt = iteration + ":" + domain
        pw = scrypt(password, salt, N = 2^16, r = 8, p = 16, keylength = 32 bytes)
        if pw is not revoked {
            return z85_encode(pw)
        }
    }
}
```

Where `scrypt()` is the SCrypt key derivation function, and `z85_encode()`
encodes the bytearray obtained from `scrypt()` to text using the [Z85
encoding](http://rfc.zeromq.org/spec:32/Z85), a variant of Base85.

Encoding passwords in Z85 ensures that the overwhelming majority of passwords
include lowercase letters, uppercase letters, numbers and symbols, like a lot
of stupid websites require.
