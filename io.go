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

/*
 * Organize data into password file protocol, then encrypt the
 * password file and write to file.  If first time writing and backups
 * allowed, make a backup.
 */

package main

import (
  "github.com/PariahVi/latchbox/import/bcrypt"
  "crypto/sha512"
  "io/ioutil"
)

func writeData() error {
  groupMap()
  var dataList [][]byte
  for x := range names {
    var data []byte
    data = append(data, strLenAppend([]byte(names[x]), 1)...)
    data = append(data, strLenAppend([]byte(usernames[x]), 1)...)
    data = append(data, strLenAppend([]byte(passwords[x]), 2)...)
    data = append(data, strLenAppend([]byte(emails[x]), 1)...)
    data = append(data, strLenAppend([]byte(urls[x]), 1)...)
    if groups[x] != "" {
      data = append(data, []byte(groupDict[groups[x]])...)
    } else {
      data = append(data, []byte{0, 0}...)
    }
    made := timeToUnix(created[x])
    data = append(data, intByte(made, 8)...)
    edited := timeToUnix(modified[x])
    data = append(data, intByte(edited, 8)...)
    data = append(data, []byte(comments[x])...)
    dataList = append(dataList, strLenAppend(data, 3))
  }
  var data []byte
  for x := range dataList {
    data = append(data, dataList[x]...)
  }
  data = append(groupHeader(), data...)
  data = append(intByte(int64(protocolVersion), 2), data...)
  salt, _ := bcrypt.Salt()
  key := hashKey(passphrase, salt)
  hashPt := sha512.New()
  hashPt.Write([]byte(data))
  ptHash := hashPt.Sum(nil)
  dataEncrypt := encrypt(data, key)
  dataEncrypt = append([]byte(salt), dataEncrypt...)
  dataEncrypt = append(dataEncrypt, ptHash...)
  err := ioutil.WriteFile(fPath, dataEncrypt, 0644)
  if err != nil {
    return err
  }
  if len(names) > 0 {
    doBackup()
  }
  return nil
}

