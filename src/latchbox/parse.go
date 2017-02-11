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
 * Parses information so the parsed information can be used and stored.
 */

package main

import (
  "errors"
  "io/ioutil"
  "strings"
)

/*
 * Parses the decrypted password file and sorts the information in
 * accordance to the protocol for use with the program.
 */
func parseFile() error {
  var err bool
  var pointer int
  var packetPointer int
  var hGroupPointer string
  if len(fileContents) >= 2 {
    pFileVersion = uint16(bytesToNum(fileContents[pointer: pointer + 2]))
  } else {
    err = true
  }
  pointer += 2
  groupPacketLen, groupPacket := parseInfo(fileContents, 4, &pointer, &err)
  if len(fileContents) - pointer + groupPacketLen >= groupPacketLen &&
       groupPacketLen > 0 && !err {
    for packetPointer < groupPacketLen && !err {
      _, hGroup := parseInfo(groupPacket, 2, &packetPointer, &err)
      if len(groupPacket) >= 2 + packetPointer && !err {
        hGroupPointer = string(groupPacket[
          packetPointer: packetPointer + 2])
      } else {
        err = true
      }
      packetPointer += 2
      if !err {
        groupDict[string(hGroup)] = hGroupPointer
      }
    }
  } else if len(groupPacket) != 0 {
    err = true
  }
  for pointer < len(fileContents) && !err {
    _, packet := parseInfo(fileContents, 3, &pointer, &err)
    packetPointer = 0
    nameLen, name := parseInfo(packet, 1, &packetPointer, &err)
    if nameLen > 0 && !inString(string(name), "/") && !err {
      names = append(names, string(name))
    } else {
      err = true
    }
    _, username := parseInfo(packet, 1, &packetPointer, &err)
    if len(packet) > packetPointer && !err {
      usernames = append(usernames, string(username))
    } else {
      err = true
    }
    _, password := parseInfo(packet, 2, &packetPointer, &err)
    if len(packet) > packetPointer && !err {
      passwords = append(passwords, string(password))
    } else {
      err = true
    }
    _, email := parseInfo(packet, 1, &packetPointer, &err)
    if len(packet) > packetPointer && !err {
      emails = append(emails, string(email))
    } else {
      err = true
    }
    _, url := parseInfo(packet, 1, &packetPointer, &err)
    if len(packet) > packetPointer && !err {
      urls = append(urls, string(url))
    } else {
      err = true
    }
    var group string
    if len(packet) - packetPointer >= 2 && !err {
      for path, point := range groupDict {
        if point == string(packet[packetPointer: packetPointer + 2]) {
          group = path
          if path != "" && point != "" {
            if group[0] == ' ' || group[0] == '/' ||
                group[len(group) - 1] == '/' ||
                inString(group, "//") ||
                inString(group, "/ ") {
              err = true
            }
          } else if path == "" && point != "" {
            err = true
          }
        }
      }
      groups = append(groups, group)
    } else {
      err = true
    }
    packetPointer += 2
    getTime(packet, &created, &packetPointer, &err)
    getTime(packet, &modified, &packetPointer, &err)
    var comment string
    if len(packet) - packetPointer >= 0 &&
        len(packet) - packetPointer < 65536 && !err {
      comment = string(packet[packetPointer:])
      comments = append(comments, comment)
    } else {
      err = true
    }
  }
  nameGroupsList := nameGroups()
  if duplicateNameGroups(nameGroupsList) {
    err = true
  }
  if err {
    lock()
    contentString = "Corrupted Password File"
    return errors.New("Corrupted Password File")
  }
  return nil
}

/*
 * Returns the length of the next packet section along with the content of
 * the packet section.
 */
func parseInfo(packet []byte, byteLen int, pointer *int, err *bool) (
    packetLen int, content []byte) {
  var pLen int
  var pContent []byte
  if len(packet) - *pointer >= byteLen && !*err {
    pLen = int(bytesToNum(packet[*pointer: *pointer + byteLen]))
  } else {
    *err = true
  }
  *pointer += byteLen
  if len(packet) >= *pointer + pLen && !*err {
    pContent = packet[*pointer: *pointer + pLen]
  } else {
    *err = true
  }
  *pointer += pLen
  return pLen, pContent
}

/*
 * Checks to see if the encrypted password file (fc) looks legitimate for
 * length, then parses out the iterations and ciphertext (ct).  If the length
 * of fc isn't at least 36 (length of iteration bytes, salt and AES256-GCM IV),
 * an error is returned.
 */
func parseCt(fc []byte) (iterations int, salt, ct []byte, err error) {
  if len(fc) < 36 {
    return 0, nil, nil, errors.New("latchbox file content too short")
  }
  return int(bytesToNum(fc[:4])), fc[4: 36], fc[36:], nil
}

/*
 * Parses the config file to figure out the default password file location
 * and if backups are allowed.
 */
func configParse() {
  configFile := configDir + "config"
  content, err := ioutil.ReadFile(configFile)
  if err == nil {
    configSplit := strings.Split(string(content), "\n")
    for x := range configSplit {
      configLineSplit := strings.Split(configSplit[x], "=")
      for len(configLineSplit[0]) > 0 && (configLineSplit[0][0] == ' ' ||
          configLineSplit[0][len(configLineSplit[0]) - 1] == ' ') {
        if configLineSplit[0][0] == ' ' {
          configLineSplit[0] = configLineSplit[0][1:]
        } else {
          configLineSplit[0] = configLineSplit[0][
            :len(configLineSplit[0]) - 1]
        }
      }
      if len(configLineSplit) > 1 {
        first := strings.Index(configLineSplit[1], "\"") + 1
        last := strings.LastIndex(configLineSplit[1], "\"")
        if first > last {
          first -= 1
        }
        if configLineSplit[0] == "makeBackups" {
          if strings.ToLower(
              configLineSplit[1][first: last]) == "true" {
            backup = true
          }
        } else if configLineSplit[0] == "defaultPasswordFile" {
          defaultFile = configLineSplit[1][first: last]
        }
      }
    }
  } else {
    panic("Unable to Read Config File " + configFile)
  }
}
