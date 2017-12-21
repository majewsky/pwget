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

Many systems enforce some sort of password policy, e.&nbsp;g. the password must
contain at least one upper-case character, at least one digit, etc.
To avoid the necessity of tweaking a pwget-generated password in order to be
able to use it on such a system, pwget has the following command line switches
that influence the password generation:
- `[ -l | --maxlength ] <max_len>`: The generated password will have a length of `max_len` characters at most
- `-A | --upper`: The generated password will contain at least one upper-case letter
- `-a | --lower`: The generated password will contain at least one lower-case letter
- `-s | --special`: The generated password will contain at least one special character
- `-d | --digit`: The generated password will contain at least one digit

## Algorithm

In pseudo-code:

```
func getPassword(masterPassword, domain) {
    for iteration in 0..infinity {
        salt = iteration + ":" + domain
        pw = scrypt(password, salt, N = 2^16, r = 8, p = 16, keylength = 32 bytes)
        if pw is not revoked {
            return pw
        }
    }
}
```

Where `scrypt()` is the SCrypt key derivation function.
