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

/* A Console Based Password Management Program */

package main

import (
  "math"
  "time"
)

/*
 * Get YYYY-MM-DD hh:mm:ss timestamp out of 8 bytes (protocol version > 1)
 * or 4 bytes (protocol version 1).
 */
func getTime(packet []byte, entryList *[]string, pointer *int,
    pFileVersion uint16, err *bool) {
  var timeLen int
  if pFileVersion != 1 && len(packet) - *pointer >= 8 && !*err {
    timeLen = 8
  } else if pFileVersion == 1 && len(packet) - *pointer >= 4 &&
      !*err {
    timeLen = 4
  }
  if timeLen > 0 {
    timeByteString := string(packet[*pointer: *pointer + timeLen])
    var cInt float64
    for x := range timeByteString {
      cInt += float64(timeByteString[x]) * math.Pow(256, float64(timeLen -
         1 - x))
    }
    timestamp := time.Unix(int64(cInt), 0).Format(timeLayout)
    *entryList = append(*entryList, timestamp)
  } else {
    *err = true
  }
  if pFileVersion != 1 {
    *pointer += 4
  }
  *pointer += 4
}

/* Convert YYYY-MM-DD hh:mm:ss timestamp to local Unix time. */
func timeToUnix(value string) int64 {
  local, _ := time.LoadLocation("Local")
  toTime, _ := time.ParseInLocation(timeLayout, value, local)
  return toTime.Unix()
}

