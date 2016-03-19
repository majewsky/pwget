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
job to come up with a consistent scheme for these `<domain>` values, because
pwget does not enforce anything. The following three, for example, will
generate completely different passwords:

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
