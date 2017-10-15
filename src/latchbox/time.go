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
 * Organize data into password file protocol, then encrypt the
 * password file and write to file.  If first time writing and backups
 * allowed, make a backup.  Also does anything that involves reading and
 * writing to a file.
 */

package main

import (
  "time"
)

/*
 * Tests to see how many iterations of PBKDF2 need to happen to equal 0.5
 * seconds.  100000 is the lowest possible amount of iterations.
 */
func getIterationsFromPBKDF2Test() {
  var iter uint32 = 100000
  var testIter uint32 = 10000
  var goalTime int64 = 500000000
  startTime := time.Now()
  generatePBKDF2Key([]byte("Test"), []byte("salt"), testIter)
  endTime := time.Since(startTime).Nanoseconds()
  factor := goalTime / endTime
  var finalIter uint32 = testIter * uint32(factor)
  if finalIter < 100000 {
    finalIter = iter
  }
  iterations = finalIter
}
