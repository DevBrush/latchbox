/*-
 * Copyright (C) 2014-2015, PariahVi
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
  "github.com/PariahVi/latchbox/import/bcrypt"
  "crypto/aes"
  "crypto/cipher"
  "crypto/rand"
  "crypto/sha256"
)

/*
 * Uses bcrypt with a cost value of 12 and salt to hash passValue, then
 * uses SHA256 to hash the value that was hashed with bcrypt to create a
 * 32-bit byte slice to encrypt the password file using AES256.
 */
func hashKey(passValue, salt string) []byte {
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
