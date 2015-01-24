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
  var byteList []byte
  y := len(s)
  var byteString []byte
  for x := byteNum - 1; x > -1; x-- {
    z := y / int(math.Pow(256, float64(x)))
    byteList = append(byteList, uint8(z))
    y -= z * int(math.Pow(256, float64(x)))
  }
  for x := range byteList {
    byteString = append(byteString, byteList[x])
  }
  byteString = append(byteString, s...)
  return byteString
}

/* Converts i to to a byte slice of byteNum length. */
func intByte(i int64, byteNum int) []byte {
  var byteList []byte
  y := i
  var byteString []byte
  for x := byteNum - 1; x > -1; x-- {
    z := y / int64(math.Pow(256, float64(x)))
    byteList = append(byteList, uint8(z))
    y -= z * int64(math.Pow(256, float64(x)))
  }
  for x := range byteList {
    byteString = append(byteString, byteList[x])
  }
  return byteString
}

/* Converts byteString to an int */
func getLen(byteString []byte) int {
  solution := float64(0)
  a := len(byteString)
  y := a - 1
  for x := 0; x < a; x ++ {
    solution += float64(byteString[x]) * math.Pow(256, float64(y))
    y -= 1
  }
  return int(solution)
}
