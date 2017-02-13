/*-
 * Copyright (C) 2014-2017, Vi Grey
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
  "golang.org/x/crypto/pbkdf2"
  "crypto/aes"
  "crypto/cipher"
  "crypto/hmac"
  "crypto/rand"
  "crypto/sha256"
  "crypto/sha512"
  "math/big"
  "strconv"
)

/*
 * Generates a key from auth using HMAC-SHA256 based PBKDF2 with 100,000
 * iterations
 */
func generatePBKDF2Key(auth, salt []byte) []byte {
  return pbkdf2.Key(auth, salt, 100000, 32, sha256.New)
}

// Encrypts plaintext using key with AES256-GCM and returns the ciphertext
func encrypt(message, key []byte) []byte {
  var err error
  block, err := aes.NewCipher(key)
  if err != nil {
    panic(err)
  }
  /*
   * Add one to aesGCMIV, roll value over to 0 if the uint64 value hits
   * 2 ** 64 - 1
   */
  aesGCMIV = int64(uint64(aesGCMIV) + 1 % 18446744073709551615)
  // Pad aesGCMIV value with 4 random bytes to create the iv value
  iv := append(numToBytes(aesGCMIV, 8), randByteArray(4)...)
  mode, err := cipher.NewGCM(block)
  if err != nil {
    return []byte{}
  }
  ciphertext := mode.Seal(nil, iv, message, nil)
  return append(iv, ciphertext...)
}

/*
 * Decrypts ciphertext using key with AES256-GCM and returns the plaintext and
 * whether or not the content was decrypted
 */
func decrypt(ciphertext, key []byte) ([]byte, bool) {
  if len(ciphertext) < 12 {
    return nil, false
  }
  block, err := aes.NewCipher(key)
  if err != nil {
    panic(err)
  }
  iv := ciphertext[:12]
  aesGCMIV = bytesToNum(iv[:8])
  ct := ciphertext[12:]
  mode, err := cipher.NewGCM(block)
  block = nil
  if err != nil {
    panic(err)
  }
  plaintext, err := mode.Open(nil, iv, ct, nil)
  mode = nil
  if err != nil {
    return nil, false
  }
  return plaintext, true
}

// Generates a random byte array of size length
func randByteArray(size int) []byte {
  randValue := make([]byte, size)
  if _, err := rand.Read(randValue); err != nil {
    panic(err)
  }
  return randValue
}

// Get a random int between 0 and number
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

/*
 * Creates a new HMAC of message using key as the secret key with the hashing
 * algorithm SHA512
 */
func newHMAC(message string, key []byte) string {
  sig := hmac.New(sha512.New, key)
  sig.Write([]byte(message))
  return string(sig.Sum(nil))
}
