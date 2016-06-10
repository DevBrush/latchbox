/*-
 * Copyright (C) 2014-2016, Vi Grey
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
 * Handles anything that manimulates groups.
 */

package main

import (
  "github.com/DevBrush/latchbox/import/sortutil"
  "strconv"
)

/*
 * Creates a string with the group name combinations along with a number
 * in square brackets ahead of it to indicate that group name combination
 * option for selecting the group name entry to use.
 */
func displayNameGroups() string {
  content := ""
  nameGroupsList := nameGroups()
  for x := range nameGroupsList {
    content += "[" + strconv.Itoa(x + 1) + "] " + nameGroupsList[x] + "\n"
  }
  return content[:len(content) - 1]
}

/*
 * Returns a case insensitive sorted string slice of the groups
 * concatenated with the names.
 */
func nameGroups() []string {
  var nameGroupsList []string
  for x := range names {
    if groups[x] == "" {
      nameGroupsList = append(nameGroupsList, names[x])
    } else {
      nameGroupsList = append(nameGroupsList, groups[x] + "/" + names[x])
    }
  }
  nameGroupsList = ciSort(nameGroupsList)
  return nameGroupsList
}

/* Case insentitive sorts the string slice list. */
func ciSort(list []string) []string {
  var nameGroupsList []string
  nameGroupsList = append(nameGroupsList, list...)
  for x := range list {
    list[x] += "/:"
  }
  sortutil.CiAsc(list)
  var order []int
  for x := range list {
    list[x] = list[x][:len(list[x]) - 2]
    for y := range nameGroupsList {
      if list[x] == nameGroupsList[y] {
        order = append(order, y)
      }
    }
  }
  orderList = order
  return list
}

/* Make map of [groupName]groupPointer (group pointer can be up to 65535). */
func groupMap() {
  i := 1
  groupDict = make(map[string]string)
  for x := range groups {
    var inGroupDict bool
    group := groups[x]
    for y := range groupDict {
      if y == group {
        inGroupDict = true
      }
    }
    if !inGroupDict {
      groupDict[group] = string(intByte(int64(i), 2))
      i++
    }
  }
}

/* Returns byte slice of protocol for groups and group pointers. */
func groupHeader() []byte {
  var groupData []byte
  for x := range groupDict {
    groupData = append(groupData, strLenAppend([]byte(x), 2)...)
    groupData = append(groupData, []byte(groupDict[x])...)
  }
  groupData = strLenAppend(groupData, 4)
  return groupData
}

/* Return true if there are duplicate values in nameGroupList. */
func duplicateNameGroups(nameGroupsList []string) bool {
  dup := make(map[string]bool)
  for _, x := range nameGroupsList {
    if !dup[x] {
      dup[x] = true
    } else {
      return true
    }
  }
  return false
}
