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

/* A Console Based Password Management Program */

package main

import (
  "fmt"
  "os"
  "runtime"
  "strings"
)

const (
  /* Protocol Version to save password file under.*/
  protocolVersion = 2
  versionNum = "2.0.1"
  version = "v" + versionNum
  title = "LatchBox " + version + " (Esc:QUIT"
  /*
   * uppercase, lowercase, digits and punctuation are used to generate
   * random passwords.
   */
  uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  lowercase = "abcdefghijklmnopqrstuvwxyz"
  digits = "1234567890"
  punctuation = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
  /* YYYY-MM-DD hh:mm:ss 24-hour time (computer's localtime) */
  timeLayout = "2006-01-02 15:04:05"
  /* YYYYMMDDhhmmss 24-hour time (computer's localtime) */
  backupLayout = "20060102150405"
)

var (
  contentCopied, helpFlag, versionFlag bool
  passChars []bool
  backupContents, fileContents []byte
  bottomCaption, configDir, contentExtra, contentString, csvFile string
  ctrlCValue, defaultFile, entryData, errMsg, fPath, key, key1, location string
  locationTitle, options, passphrase, tmpDefault, tmpPassphrase string
  topTitle, value string
  menu = "Welcome"
  comments, created, emails, groups, modified, names, newValue []string
  passwords, urls, usernames []string
  menuList = []string{menu}
  entryNumber, h, passLen, top, w int
  aesGCMIV int64
  orderList []int
  pFileVersion uint16
  groupDict = make(map[string]string)
  orderDict = make(map[string]string)
  step = make([]bool, 13)
  backup, backupSaved, checksum, ctrlC, keyDownPressed, keyUpPressed, omit bool
  passwordInput, show bool
  edit_box EditBox
)

/*
 * Resets variables and brings the user back to the Welcome menu to either
 * make a NEW password file or OPEN an old one.
 */
func lock() {
  passChars = make([]bool, 0)
  newValue = make([]string, 0)
  passLen = 0
  entryData = ""
  fPath = ""
  value = ""
  passphrase = ""
  key = ""
  location = ""
  backupSaved = false
  backupContents = make([]byte, 0)
  fileContents = make([]byte, 0)
  names = make([]string, 0)
  usernames = make([]string, 0)
  passwords = make([]string, 0)
  emails = make([]string, 0)
  urls = make([]string, 0)
  groups = make([]string, 0)
  comments = make([]string, 0)
  created = make([]string, 0)
  modified = make([]string, 0)
  groupDict = make(map[string]string)
  orderDict = make(map[string]string)
  menu = "Welcome"
  menuList = []string{menu}
  step = make([]bool, 13)
  key1 = ""
  bottomCaption = ""
  contentString = ""
  orderList = make([]int, 0)
}

func main() {
  /* Check if BSD, GNU/Linux or Mac OSX. */
  if runtime.GOOS == "windows" || runtime.GOOS == "plan9" {
    panic("Unsupported Operating System")
  }
  for i := 1; i < len(os.Args); i++ {
    if len(os.Args[i]) > 2 && strings.Index(os.Args[i], "--") == 0 {
      if os.Args[i][2:] == "help" {
        helpFlag = true;
      } else if os.Args[i][2:] == "version" {
        versionFlag = true;
      } else if os.Args[i][2:] != "" {
        fmt.Printf("latchbox: unrecognized option '%s'\nTry 'latchbox " +
                   "--help' for more information.\n", string(os.Args[i]))
        os.Exit(1)
      }
    } else if len(os.Args[i]) > 1 && os.Args[i][0] == '-' &&
        strings.Index(os.Args[i], "--") != 0 {
      for x := 1; x < len(os.Args[i]); x++ {
        if os.Args[i][x] == 'h' {
          helpFlag = true;
        } else {
          fmt.Printf("latchbox: invalid option -- '%s'\nTry 'latchbox " +
                     "--help' for more information.\n", string(os.Args[i][x]))
          os.Exit(1)
        }
      }
    } else if strings.Index("--", os.Args[i]) != 0 {
      fmt.Printf("latchbox: invalid option -- '%s'\nTry 'latchbox " +
                 "--help' for more information.\n", string(os.Args[i]))
      os.Exit(1)
    }
  }
  if helpFlag || versionFlag {
    if helpFlag {
      helpPrint()
    } else {
      versionPrint()
    }
  } else {
    cli()
  }
}
