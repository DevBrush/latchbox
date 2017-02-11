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

/*
 * Handles functions that involve translating bytes to other formats or
 * translating other formats to bytes.  Also handles inString function.
 */

package main

import (
  "math"
  "strings"
)

/* Checks if the string char is in the string input. */
func inString(input, char string) bool {
  if strings.Index(input, char) > -1 {
    return true
  }
  return false
}

/*
 * Returns byteNum bytes that signify the length of s and appends s
 * to the bytes.
 */
func strLenAppend(s []byte, byteNum int) []byte {
  return append(numToBytes(int64(len(s)), byteNum), s...)
}

// Converts bytes b to an integer
func bytesToNum(b []byte) int64 {
  var length int64
  y := len(b) - 1
  for x := 0; x < len(b); x++ {
    length += int64(b[x]) * int64(math.Pow(256, float64(y)))
    y--
  }
  return length
}

// Converts num to a byte array of size int
func numToBytes(num interface{}, size int) []byte {
  var numBytes []byte
  y := size - 1
  switch numVal := num.(type) {
  case int64:
    for x := 0; x < size; x++ {
      byteVal := byte(numVal / int64(math.Pow(256, float64(y))))
      numVal -= int64(byteVal) * int64(math.Pow(256, float64(y)))
      numBytes = append(numBytes, byteVal)
      y--
    }
  case int:
    for x := 0; x < size; x++ {
      byteVal := byte(numVal / int(math.Pow(256, float64(y))))
      numVal -= int(byteVal) * int(math.Pow(256, float64(y)))
      numBytes = append(numBytes, byteVal)
      y--
    }
  default:
    panic("Type of num must be int or int64")
  }
  return numBytes
}
