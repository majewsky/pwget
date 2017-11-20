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
	"encoding/hex"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/ogier/pflag"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	//check arguments
	domain, doRevoke, maxLen, needsUpper, needsLower, needsSpecial, needsDigit := ParseArguments()

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
		passwordStr = hex.EncodeToString(password)

		//this is the correct password, unless it has been revoked
		hash := sha256.Sum256([]byte(passwordStr))
		hashStr = hex.EncodeToString(hash[:])
		if isSHA256OfRevokedPassword[hashStr] {
			os.Stderr.Write([]byte("\x1B[37m" + passwordStr + " is revoked\x1B[0m\n"))
			continue
		}
		break
	}

	//now, we either print or revoke the thing
	if doRevoke {
		os.Stderr.Write([]byte("Revoking " + passwordStr + "\n"))
		err := AppendToRevocationList(hashStr)
		FailOnError("update revocation list", err)
	} else {

		//shorten password
		if maxLen > 0 && maxLen < len(passwordStr) {
			passwordStr = passwordStr[:maxLen]
		}

		//handle domain properties
		password := []byte(passwordStr)
		var offset uint = uint(len(password))

		if needsUpper {
			includeInPassword(password, &offset, "[A-Z]", 'A')
		}
		if needsLower {
			includeInPassword(password, &offset, "[a-z]", 'a')
		}
		if needsSpecial {
			includeInPassword(password, &offset, "[_\\-]", '-')
		}
		if needsDigit {
			includeInPassword(password, &offset, "[0-9]", '0')
		}

		os.Stdout.Write(password)
		os.Stdout.Sync()
		//write the newline on stderr only, so that it is not copied when
		//piping stdout to xsel or xclip
		os.Stderr.Write([]byte("\n"))
	}
}

//includeInPassword adds the character of a specific class to the password if not already present
func includeInPassword(password []byte, offset *uint, classPattern string, char byte) {
	match, err := regexp.MatchString(classPattern, string(password))
	if err != nil {
		panic(err)
	}
	if !match {
		password[*offset-1] = char
		*offset--
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
func ParseArguments() (domain string, revoke bool, maxLen int, upper bool, lower bool, special bool, digit bool) {

	//define flags
	var help bool
	pflag.BoolVarP(&revoke, "revoke", "r", false, "Revoke the current password for the domain")
	pflag.BoolVarP(&help, "help", "h", false, "Show information on program usage")
	pflag.BoolVarP(&upper, "upper", "A", false, "Generated password will contain a upper-case character")
	pflag.BoolVarP(&lower, "lower", "a", false, "Generated password will contain a lower-case character")
	pflag.BoolVarP(&special, "special", "s", false, "Generated password will contain the special character '-'")
	pflag.BoolVarP(&digit, "digit", "d", false, "Generated password will contain a digit")
	pflag.IntVarP(&maxLen, "maxlength", "l", 0, "Maximum length to which the generated password will be shortened. 0 means don't shorten.")

	//parse and check flags
	pflag.Parse()
	if maxLen < 0 {
		os.Stderr.Write([]byte("error: maximum length must not be negative\n"))
		os.Exit(1)
	}

	//check remaining arguments
	if len(pflag.Args()) > 1 {
		os.Stderr.Write([]byte("error: multiple domains\n"))
		os.Exit(1)
	}

	if len(pflag.Args()) <= 0 || help {
		os.Stderr.Write([]byte("Usage: " + os.Args[0] + " [-r|--revoke] [-l|--maxlength <max_len>] <domain>\n"))
		os.Exit(1)
	}

	domain = pflag.Args()[0]
	return domain, revoke, maxLen, upper, lower, special, digit
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
	return os.Getenv("HOME") + "/.pwget-revocation"
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
