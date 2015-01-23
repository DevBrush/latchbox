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
 * allowed, make a backup.  Also does anything that involves reading and
 * writing to a file.
 */

package main

import (
  "github.com/PariahVi/latchbox/import/bcrypt"
  "crypto/sha512"
  "encoding/csv"
  "errors"
  "io/ioutil"
  "os"
  "os/user"
  "runtime"
  "strings"
  "time"
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

/*
 * Makes backup files (and a backup directory inside of the latchbox
 * directory if it doesn't exist) and makes a copy of the password file
 * as it was when it was opened on the first time it is saved after
 * opening it.
 */
func doBackup() {
  if !backupSaved {
    if backup && len(backupContents) > 0 {
      backSlashSplit := strings.Split(fPath, "\\")
      slashSplit := strings.Split(fPath, "/")
      fileName := slashSplit[len(slashSplit) - 1]
      if len(backSlashSplit) > 1 {
        fileName = backSlashSplit[len(backSlashSplit) - 1]
      }
      fileName = strings.Split(fileName, ".")[0]
      fileName += "-"
      backupDir := configDir + "backup/"
      backupFile := fileName + time.Now().Local().Format(backupLayout) +
        ".lbp"
      os.MkdirAll(backupDir, 0755)
      ioutil.WriteFile(backupDir + backupFile, backupContents, 0644)
      backupSaved = true
    }
  }
}

/*
 * Makes latchbox directory if one doesn't exist and creates config
 * if it doesn't exist.  If config.txt exists, but not config, config.txt
 * will be renamed to config.
 */
func makeConfig() {
  usr, _ := user.Current()
  configDir = usr.HomeDir + "/.latchbox/"
  configContent := "makeBackups = \"true\"\n\ndefaultPasswordFile = \"" +
    configDir + "passwords.lbp\""
  if _, err := os.Stat(configDir); err != nil {
    os.MkdirAll(configDir, 0755)
    ioutil.WriteFile(configDir + "config", []byte(configContent), 0644)
  } else {
    content, err := ioutil.ReadFile(configDir + "config")
    if err != nil || len(content) == 0 {
      content, err := ioutil.ReadFile(configDir + "config.txt")
      if err == nil && len(content) != 0 {
        os.Rename(configDir + "config.txt", configDir + "config")
      } else {
        ioutil.WriteFile(configDir + "config",
          []byte(configContent), 0644)
      }
    }
  }
}

/*
 * Reads the contents of a LastPass .csv file and adds the contents and saves
 * the password file with the added content.
 */
func importCSV(location string) error {
  csvLocation, err := os.Open(location)
  if err != nil {
    contentString = "Cannot Open CSV File in " + location
    return err
  }
  csvLabels := make(map[int]string)
  r := csv.NewReader(csvLocation)
  csvContent, err := r.ReadAll()
  csvLocation.Close()
  if err != nil {
    return err
  }
  for x := range csvContent[0] {
    csvLower := strings.ToLower(csvContent[0][x])
    if csvLower == "name" || csvLower == "account" {
      csvLabels[x] = "name"
    } else if csvLower == "username" || csvLower == "login name" {
      csvLabels[x] = "username"
    } else if csvLower == "password" {
      csvLabels[x] = "password"
    } else if csvLower == "url" || csvLower == "web site" {
      csvLabels[x] = "url"
    } else if csvLower == "grouping" || csvLower == "group" {
      csvLabels[x] = "group"
    } else if csvLower == "extra" || csvLower == "comments" {
      csvLabels[x] = "comment"
    }
  }
  if len(csvLabels) == 0 {
    contentString = "No Suitable Labels for Import Data"
    return errors.New("No Suitable Labels for Import Data")
  }
  namesLen := len(names[:])
  usernamesLen := len(usernames[:])
  passwordsLen := len(passwords[:])
  urlsLen := len(urls[:])
  groupsLen := len(groups[:])
  commentsLen := len(comments[:])
  if len(csvContent) > 1 {
    for x := range csvContent[1:] {
      x += 1
      for y := range csvContent[x] {
        content := csvContent[x][y]
        if csvLabels[y] == "name" {
          if len(names) == namesLen + x - 1 {
            if len(content) > 0 && len(content) < 256 {
              name := strings.Replace(content, "/", "\\", -1)
              names = append(names, name)
            } else {
              contentString = "Name is Not an Expected Length"
              return errors.New("Name is Not an Expected Length")
            }
          } else {
            contentString = "Too Many Names in One Entry"
            return errors.New("Too Many Names in One Entry")
          }
        } else if csvLabels[y] == "username" {
          if len(usernames) == usernamesLen + x - 1 {
            if len(content) >= 0 && len(content) < 256 {
              usernames = append(usernames, content)
            } else {
              contentString = "Username is Not an Expected Length"
              return errors.New("Username is Not an Expected " +
                        "Length")
            }
          } else {
            contentString = "Too Many Usernames in One Entry"
            return errors.New("Too Many Usernames in One Entry")
          }
        } else if csvLabels[y] == "password" {
          if len(passwords) == passwordsLen + x - 1 {
            if len(content) >= 0 && len(content) < 65536 {
              passwords = append(passwords, content)
            } else {
              contentString = "Password is Not an Expected Length"
              return errors.New("Password is Not an Expected " +
                        "Length")
            }
          } else {
            contentString = "Too Many Passwords in One Entry"
            return errors.New("Too Many Passwords in One Entry")
          }
        } else if csvLabels[y] == "url" {
          if len(urls) == urlsLen + x - 1 {
            if len(content) >= 0 && len(content) < 256 {
              if strings.ToLower(content) == "http://" ||
                  strings.ToLower(content) == "https://" {
                urls = append(urls, "")
              } else {
                urls = append(urls, content)
              }
            } else {
              contentString = "URL is Not an Expected Length"
              return errors.New("URL is Not an Expected Length")
            }
          } else {
            contentString = "Too Many URLs in One Entry"
            return errors.New("Too Many URLs in One Entry")
          }
        } else if csvLabels[y] == "group" {
          if len(groups) == groupsLen + x - 1 {
            var group string
            if len(content) >= 0 && len(content) < 256 {
              for z := range content {
                if content[z] == '/' {
                  group += "\\"
                } else if content[z] == '\\' {
                  group += "/"
                } else {
                  group += string(content[z])
                }
              }
              if group[0] == ' ' || group[0] =='/' ||
                  group[len(group) - 1] == '/' ||
                  inString(group, "//") ||
                  inString(group, "/") {
                contentString = "Invalid Group Name " + group
                return errors.New("Invalid Group Name " + group)
              }
              groups = append(groups, group)
            } else {
              contentString = "Group Name is Not an Expected " +
                "Length"
              return errors.New("Group Name is Not an Expected " +
                        "Length")
            }
          } else {
            contentString = "Too Many Group Names In One Entry"
            return errors.New("Too Many Group Names in One Entry")
          }
        } else if csvLabels[y] == "comment" {
          if len(comments) == commentsLen + x - 1 {
            if len(content) >= 0 && len(content) < 65536 {
              comments = append(comments, content)
            } else {
              contentString = "Comment is Not an Expected Length"
              return errors.New("Comment is Not an Expected " +
                        "Length")
            }
          } else {
            contentString = "Too Many URLs in One Entry"
            return errors.New("Too Many URLs in One Entry")
          }
        }
      }
      if len(names) <= namesLen + x - 1 {
        names = append(names, "")
      }
      if len(usernames) <= usernamesLen + x - 1 {
        usernames = append(usernames, "")
      }
      if len(passwords) <= passwordsLen + x - 1 {
        passwords = append(passwords, "")
      }
      if len(urls) <= urlsLen + x - 1 {
        urls = append(urls, "")
      }
      if len(groups) <= groupsLen + x - 1 {
        groups = append(groups, "")
      }
      if len(comments) <= commentsLen + x - 1 {
        comments = append(comments, "")
      }
      emails = append(emails, "")
      create := time.Now().Format(timeLayout)
      created = append(created, create)
      modified = append(modified, create)
    }
    nameGroupsList := nameGroups()
    if duplicateNameGroups(nameGroupsList) {
      contentString = "Duplicate Name/Group Combination"
      return errors.New("Duplicate Name/Group Combination")
    }
  } else {
    contentString = "No Contents in CSV File"
    return errors.New("No Contents in CSV File")
  }
  err = writeData()
  if err != nil {
    contentString = "Unable to Modify Password File " +
      "(Write Error)"
    return errors.New("Unable to Modify Password File")
  }
  contentString = "CSV File Imported from " + location + "!\n\n" +
    "Don't forget to fully delete the CSV file when you " +
    "don't need it anymore.  It is best to shred and delete " +
    "the file for security by using:\n\n"
  if runtime.GOOS == "darwin" {
    contentString += "srm -sz " + location
  } else {
    contentString += "shred -z " + location + "; rm " + location
  }
  return nil
}

/*
 * Creates a LastPass .csv file that can be imported to LastPass and
 * KeePass.
 */
func exportCSV(location string) error {
  csvLocation, err := os.Create(location)
  if err != nil {
    return err
  }
  w := csv.NewWriter(csvLocation)
  w.Write([]string{"name", "username", "password", "url",
      "grouping", "extra"})
  var writeErr error
  for x := range names {
    var newGroup string
    for y := range groups[x] {
      if groups[x][y] == '/' {
        newGroup += "\\"
      } else if groups[x][y] == '\\' {
        newGroup += "/"
      } else {
        newGroup += string(groups[x][y])
      }
    }
    var url string
    if len(urls[x]) == 0 {
      url = "http://"
    } else {
      url = urls[x]
    }
    writeErr = w.Write([]string{names[x], usernames[x], passwords[x],
             url, newGroup, comments[x]})
  }
  if writeErr != nil {
    os.Remove(location)
    return writeErr
  }
  w.Flush()
  contentString = "CSV File Created in " + location + "!\n\n" +
    "Don't forget to fully delete the CSV file when you " +
    "don't need it anymore.  It is best to shred and delete " +
    "the file for security by using:\n\n"
  if runtime.GOOS == "darwin" {
    contentString += "srm -sz " + location
  } else {
    contentString += "shred -z " + location + "; rm " + location
  }
  csvLocation.Close()
  return nil
}
