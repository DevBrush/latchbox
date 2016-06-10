/*-
 * Copyright (C) 2015-2016 Vi Grey. All rights reserved.
 * Copyright (C) 2011 James Keane <james.keane@gmail.com>. All rights reserved.
 * Copyright (C) 2006 Damien Miller <djm@mindrot.org>.
 * Copyright (C) 2011 ZooWar.com, All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following disclaimer
 *    in the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name of weekendlogic nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package bcrypt

import (
  "bytes"
  "crypto/rand"
  "encoding/base64"
  "errors"
  "strconv"
  "strings"
)

var (
  InvalidRounds = errors.New("bcrypt: Invalid rounds parameter")
  InvalidSalt   = errors.New("bcrypt: Invalid salt supplied")
)

const (
  MaxRounds      = 31
  MinRounds      = 4
  DefaultRounds  = 12
  SaltLen        = 16
  BlowfishRounds = 16
)

var enc = base64.NewEncoding("./ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                             "abcdefghijklmnopqrstuvwxyz0123456789")

/*
 * Helper function to build the bcrypt hash string
 * payload takes :
 *    * []byte -> which it base64 encodes it (trims padding "=") and writes it
 *      to the buffer
 *    * string -> which it writes straight to the buffer
 */
func build_bcrypt_str(minor byte, rounds uint, payload ...interface{}) []byte {
  rs := bytes.NewBuffer(make([]byte, 0, 61))
  rs.WriteString("$2")
  if minor >= 'a' {
    rs.WriteByte(minor)
  }
  rs.WriteByte('$')
  if rounds < 10 {
    rs.WriteByte('0')
  }
  rs.WriteString(strconv.FormatUint(uint64(rounds), 10))
  rs.WriteByte('$')
  for _, p := range payload {
    if pb, ok := p.([]byte); ok {
      rs.WriteString(strings.TrimRight(enc.EncodeToString(pb), "="))
    } else if ps, ok := p.(string); ok {
      rs.WriteString(ps)
    }
  }
  return rs.Bytes()
}

/* Salt generation */
func Salt(rounds ...int) (string, error) {
  rb, err := SaltBytes(rounds...)
  return string(rb), err
}

func SaltBytes(rounds ...int) (salt []byte, err error) {
  r := DefaultRounds
  if len(rounds) > 0 {
    r = rounds[0]
    if r < MinRounds || r > MaxRounds {
      return nil, InvalidRounds
    }
  }
  rnd := make([]byte, SaltLen)
  read, err := rand.Read(rnd)
  if read != SaltLen || err != nil {
    return nil, err
  }
  return build_bcrypt_str('a', uint(r), rnd), nil
}

func consume(r *bytes.Buffer, b byte) bool {
  got, err := r.ReadByte()
  if err != nil {
    return false
  }
  if got != b {
    r.UnreadByte()
    return false
  }
  return true
}

func Hash(password string, salt ...string) (ps string, err error) {
  var s []byte
  var pb []byte
  if len(salt) == 0 {
    s, err = SaltBytes()
    if err != nil {
      return
    }
  } else if len(salt) > 0 {
    s = []byte(salt[0])
  }
  pb, err = HashBytes([]byte(password), s)
  return string(pb), err
}

func HashBytes(password []byte, salt ...[]byte) (hash []byte, err error) {
  var s []byte
  if len(salt) == 0 {
    s, err = SaltBytes()
    if err != nil {
      return
    }
  } else if len(salt) > 0 {
    s = salt[0]
  }
  /*
   * TODO: use a regex? I hear go has bad regex performance a simple FSM seems
   * faster
   *      "^\\$2([a-z]?)\\$([0-3][0-9])\\$([\\./A-Za-z0-9]{22}+)"
   */
  /* Ok, extract the required information */
  minor := byte(0)
  sr := bytes.NewBuffer(s)
  if !consume(sr, '$') || !consume(sr, '2') {
    return nil, InvalidSalt
  }
  if !consume(sr, '$') {
    minor, _ = sr.ReadByte()
    if minor != 'a' || !consume(sr, '$') {
      return nil, InvalidSalt
    }
  }
  rounds_bytes := make([]byte, 2)
  read, err := sr.Read(rounds_bytes)
  if err != nil || read != 2 {
    return nil, InvalidSalt
  }
  if !consume(sr, '$') {
    return nil, InvalidSalt
  }
  var rounds64 uint64
  rounds64, err = strconv.ParseUint(string(rounds_bytes), 10, 0)
  if err != nil {
    return nil, InvalidSalt
  }
  rounds := uint(rounds64)
  /* TODO: can't we use base64.NewDecoder(enc, sr) ? */
  salt_bytes := make([]byte, 22)
  read, err = sr.Read(salt_bytes)
  if err != nil || read != 22 {
    return nil, InvalidSalt
  }
  var saltb []byte
  /*
   * encoding/base64 expects 4 byte blocks padded, since bcrypt uses only 22
   * bytes we need to go up
   */
  saltb, err = enc.DecodeString(string(salt_bytes) + "==")
  if err != nil {
    return nil, err
  }
  /*
   * cipher expects null terminated input (go initializes everything with zero
   * values so this works)
   */
  password_term := make([]byte, len(password)+1)
  copy(password_term, password)
  hashed := crypt_raw(password_term, saltb[:SaltLen], rounds)
  return build_bcrypt_str(minor, rounds, string(salt_bytes),
                          hashed[:len(bf_crypt_ciphertext)*4-1]), nil
}
