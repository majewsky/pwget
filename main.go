/*******************************************************************************
*
* Copyright 2016 Stefan Majewsky <majewsky@gmx.net>
*
* This program is free software: you can redistribute it and/or modify it under
* the terms of the GNU General Public License as published by the Free Software
* Foundation, either version 3 of the License, or (at your option) any later
* version.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
* details.
*
* You should have received a copy of the GNU General Public License along with
* this program. If not, see <http://www.gnu.org/licenses/>.
*
*******************************************************************************/

package main

import (
	"crypto/sha256"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/tilinna/z85"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	//check arguments
	domain, length, doRevoke := ParseArguments()

	//load revocation list
	isSHA256OfRevokedPassword, err := LoadRevocationList()
	FailOnError("load revocation list", err)

	//get master password
	masterPassword, err := GetMasterPassword()
	FailOnError("password query", err)

	//now we're all set, derive the password
	var passwordStr, hashStr string
	for iteration := 0; true; iteration++ {
		//get the password for this iteration
		salt := []byte(strconv.Itoa(iteration) + ":" + domain)
		password := Scrypt(masterPassword, salt)
		passwordStr = z85EncodeToString(password)

		//this is the correct password, unless it has been revoked
		hash := sha256.Sum256([]byte(passwordStr))
		hashStr = z85EncodeToString(hash[:])
		if isSHA256OfRevokedPassword[hashStr] {
			os.Stderr.Write([]byte("\x1B[37m" + hashStr + " is revoked\x1B[0m\n"))
			continue
		}
		break
	}

	//now, we either print or revoke the thing
	if doRevoke {
		os.Stderr.Write([]byte("Revoking " + hashStr + "\n"))
		err := AppendToRevocationList(hashStr)
		FailOnError("update revocation list", err)
	} else {
		//truncate password if requested
		if length > 0 && len(passwordStr) > length {
			passwordStr = passwordStr[0:length]
		}
		os.Stdout.Write([]byte(passwordStr))
		os.Stdout.Sync()
		//write the newline on stderr only, so that it is not copied when
		//piping stdout to xsel or xclip
		os.Stderr.Write([]byte("\n"))
	}
}

//FailOnError prints the given error and does not return (unless it is nil).
func FailOnError(operation string, err error) {
	if err != nil {
		os.Stderr.Write([]byte(operation + " failed: " + err.Error() + "\n"))
		os.Exit(1)
	}
}

//ParseArguments parses the os.Args. Will not return if they are malformed.
func ParseArguments() (domain string, length int, revoke bool) {
	usage := []byte("Usage: " + os.Args[0] + " [-r|--revoke] <domain> [length]\n")

	//read arguments
	var argRevoke = false
	var positionalArgs []string
	for _, arg := range os.Args[1:] {
		switch arg {
		case "-h", "--help":
			os.Stderr.Write(usage)
			os.Exit(0)
		case "-r", "--revoke":
			argRevoke = true
		default:
			positionalArgs = append(positionalArgs, arg)
		}
	}

	//need one or two arguments
	argDomain, argLength := "", 0
	switch len(positionalArgs) {
	case 1:
		argDomain = positionalArgs[0]
	case 2:
		argDomain = positionalArgs[0]
		var err error
		argLength, err = strconv.Atoi(positionalArgs[1])
		if err != nil {
			os.Stderr.Write([]byte(err.Error() + "\n"))
			os.Exit(1)
		}
	default:
		os.Stderr.Write(usage)
		os.Exit(1)
	}

	return argDomain, argLength, argRevoke
}

//GetMasterPassword queries the user for the master password.
func GetMasterPassword() ([]byte, error) {
	//prompt is written to stderr because pwget may be used in a pipe where the
	//password is read from stdout by the next program (e.g. xsel or xclip)
	os.Stderr.Write([]byte("Master password: "))
	result, err := terminal.ReadPassword(int(syscall.Stdin))
	os.Stderr.Write([]byte("\n"))
	return result, err
}

func revocationListPath() string {
	return os.Getenv("HOME") + "/.pwget2-revocation"
}

//LoadRevocationList reads the revocation list, which contains the SHA256
//hashes of all passwords which have been revoked.
func LoadRevocationList() (map[string]bool, error) {
	//try to read file
	contents, err := ioutil.ReadFile(revocationListPath())
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]bool{}, nil
		}
		return nil, err
	}

	//each hash is on one line
	hashes := strings.Split(string(contents), "\n")
	result := make(map[string]bool)
	for _, hash := range hashes {
		if hash != "" {
			result[hash] = true
		}
	}
	return result, nil
}

//AppendToRevocationList adds a new password hash to the revocation list.
func AppendToRevocationList(hash string) error {
	file, err := os.OpenFile(revocationListPath(), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	_, err = file.Write([]byte(hash + "\n"))
	if err != nil {
		return err
	}

	return file.Close()
}

//Scrypt wraps scrypt.Key() and defines its parameters so that the KDF always
//produces the same results within the scope of this program.
func Scrypt(password, salt []byte) []byte {
	result, err := scrypt.Key(password, salt, 1<<16, 8, 16, 32)
	if err != nil {
		panic(err.Error())
	}
	return result
}

func z85EncodeToString(src []byte) string {
	dst := make([]byte, z85.EncodedLen(len(src)))
	n, err := z85.Encode(dst, src)
	if err != nil {
		panic(err.Error())
	}
	return string(dst[0:n])
}
