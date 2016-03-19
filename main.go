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

import "./localdeps/golang.org/x/crypto/scrypt"

//Scrypt wraps scrypt.Key() and defines its parameters so that the KDF always
//produces the same results within the scope of this program.
func Scrypt(password, salt []byte) []byte {
	result, err := scrypt.Key(password, salt, 1<<20, 8, 16, 32)
	if err != nil {
		panic(err.Error())
	}
	return result
}

func main() {
	panic("TODO")
}
