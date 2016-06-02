/*-
 * Copyright (C) 2014-2015, Dev Brush Technology
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

package main

import (
  "github.com/DevBrush/latchbox/import/bcrypt"
  "crypto/aes"
  "crypto/cipher"
  "crypto/rand"
  "crypto/sha256"
  "math/big"
  "strconv"
)

/*
 * Uses bcrypt with a cost value of 12 and salt to hash passValue, then
 * uses SHA256 to hash the 31 byte bcrypt output value to create a
 * 32 byte slice to encrypt the password file using AES256.
 */
func hashKey(passValue, salt string) []byte {
  hashed, _ := bcrypt.Hash(passValue, salt)
  shortenedHashed := hashed[len(hashed) - 31: len(hashed)]
  hash := sha256.New()
  hash.Write([]byte(shortenedHashed))
  return hash.Sum(nil)
}

/*
 * Legacy hashKey function.  Used to derive a key from passValue in older
 * versions of LatchBox.  Eventually to be removed.
 */
func hashKeyLegacy(passValue, salt string) []byte {
  hashed, _ := bcrypt.Hash(passValue, salt)
  hash := sha256.New()
  hash.Write([]byte(hashed))
  return hash.Sum(nil)
}

/*
 * Pads the byte slice message and encrypts it using the byte string key and
 * AES256 CBC.
 */
func encrypt(message, key []byte) []byte {
  pad := (aes.BlockSize - len(message) % aes.BlockSize)
  if pad == 0 {
    pad = 16
  }
  paddedMessage := message
  for x := 0; x < pad; x++ {
    paddedMessage = append(paddedMessage, uint8(pad))
  }
  block, err := aes.NewCipher(key)
  if err != nil {
    panic(err)
  }
  ciphertext := make([]byte, len(paddedMessage))
  iv := make([]byte, aes.BlockSize)
  if _, err := rand.Read(iv); err != nil {
    panic(err)
  }
  mode := cipher.NewCBCEncrypter(block, iv)
  mode.CryptBlocks(ciphertext, paddedMessage)
  ciphertext = append(iv, ciphertext...)
  return ciphertext
}

/* Decrypts the byte slice ciphertext and unpads it. */
func decrypt(ciphertext, key []byte) []byte {
  block, err := aes.NewCipher(key)
  if err != nil {
    panic(err)
  }
  plaintext := make([]byte, len(ciphertext[aes.BlockSize:]))
  iv := ciphertext[:aes.BlockSize]
  mode := cipher.NewCBCDecrypter(block, iv)
  mode.CryptBlocks(plaintext, ciphertext[aes.BlockSize:])
  padding := 0
  if len(plaintext) > 0 {
    padding = int(plaintext[len(plaintext) - 1])
  }
  if padding > 16 {
    padding = 0
  }
  plaintext = plaintext[:len(plaintext) - padding]
  return plaintext
}

/* Get a random int between 0 and number. */
func getRandNumber(number int64) int {
  randNumber, _ := rand.Int(rand.Reader, big.NewInt(number))
  randString := randNumber.String()
  randInt, _ := strconv.Atoi(randString)
  return randInt
}

/*
 * Generate a random password with criteria ([uppercase, lowercase, digits
 * punctuation] (ulds), and lenth (pLen)).  Needs at least 4 for the
 * generated password length.  If NO was used for all criteria in ulds, a
 * password will be generated with only lowercase characters.  The password
 * is guaranteed to have at least one of every type of character allowed
 * under ulds.
 */
func genPass (pLen uint16, ulds []bool) string {
  var password []byte
  var passwordString string
  if ulds[0] {
    passwordString += uppercase
  }
  if ulds[1] {
    passwordString += lowercase
  }
  if ulds[2] {
    passwordString += digits
  }
  if ulds[3] {
    passwordString += punctuation
  }
  if passwordString == "" {
    passwordString += lowercase
  }
  for x := 0; uint16(x) < pLen; x++ {
    letter := getRandNumber(int64(len(passwordString)))
    password = append(password, passwordString[letter])
  }
  var randomValues []uint16
  for x := 0; x < 4; x++ {
    position := getRandNumber(int64(pLen))
    var bad bool
    for y := range randomValues {
      if randomValues[y] == uint16(position) {
        bad = true
      }
    }
    if bad {
      x--
    } else {
      randomValues = append(randomValues, uint16(position))
    }
  }
  characters := []string{uppercase, lowercase, digits, punctuation}
  for x := 0; x < 4; x++ {
    if ulds[x] {
      z := getRandNumber(int64(len(characters[x])))
      password[randomValues[x]] = characters[x][z]
    }
  }
  return string(password)
}
