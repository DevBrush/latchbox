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
 * Draws the termbox instance along with the content and allows for
 * resizing and shows if Ctrl-C can be used or if scrolling is allowed
 * using the up and down key.
 */

package main

import (
  "github.com/PawnTakesQueen/latchbox/import/clipboard"
  "github.com/PawnTakesQueen/latchbox/import/go-runewidth"
  "github.com/PawnTakesQueen/latchbox/import/termbox-go"
  "crypto/sha512"
  "io/ioutil"
  "os"
  "strconv"
  "strings"
  "time"
  "unicode/utf8"
)

func draw() {
  w, h = termbox.Size()
  termbox.Clear(termbox.ColorDefault, termbox.ColorDefault)
  if ctrlC {
    ctrlCValue = "  Ctrl-C:Back"
  } else {
    ctrlCValue = ""
  }
  topTitle = title + ctrlCValue + ")"
  titleSlice := multiLine(topTitle, w - 2)
  contentSlice := multiLine(contentString, w)
  optionsSlice := multiLine(options, w - 2)
  for x := range titleSlice {
    titleSlice[x] = " " + titleSlice[x]
  }
  if len(contentSlice) > h - 2 - len(optionsSlice) - len(titleSlice) {
    if keyUpPressed && top > 0 {
      top -= 1
    } else if keyDownPressed && len(contentSlice) - top > h - 2 -
        len(optionsSlice) - len(titleSlice) {
      top += 1
    }
  }
  keyUpPressed = false
  keyDownPressed = false
  if len(contentSlice) > h - 2 - len(optionsSlice) - len(titleSlice) {
    if options[len(options) - 4:] != "MOVE" {
      ud := multiLine(options + "  ↓↑:MOVE", w - 2)
      d := multiLine(options + "  ↓:MOVE", w - 2)
      if len(contentSlice) - top == h - 2 - len(d) - len(titleSlice) {
        options += "  ↑:MOVE"
      } else {
        if len(contentSlice) - top > h - 2 - len(ud) -
            len(titleSlice) && top > 0 {
          options += "  ↓↑:MOVE"
        } else if len(contentSlice) - top > h - 2 - len(d) -
            len(titleSlice) {
          options += "  ↓:MOVE"
        } else {
        options += "  ↑:MOVE"
        }
      }
    }
  }
  optionsSlice = multiLine(options, w - 2)
  for x := range optionsSlice {
    optionsSlice[x] = " " + optionsSlice[x]
  }
  if len(contentSlice) - top < h - 2 - len(optionsSlice) - len(titleSlice) &&
      top > 0 {
    top = len(contentSlice) - (h - 2 - len(optionsSlice) - len(titleSlice))
    if top < 0 {
      top = 0
    } else if len(contentSlice) - top < h - 2 - len(optionsSlice) -
        len(titleSlice) {
      top = 0
    } else if len(contentSlice) - top == h - 1 - len(optionsSlice) -
        len(titleSlice) {
      top = top + 1
    }
  }
  for x := 0; x < w; x++ {
    charLocation := ' '
    charBottomCaption := ' '
    if x - 1 < utf8.RuneCountInString(locationTitle) && x > 0 {
      charLocation = []rune(locationTitle)[x - 1]
    }
    if x < utf8.RuneCountInString(bottomCaption) {
      charBottomCaption = []rune(bottomCaption)[x]
    }
    for y := range titleSlice {
      charTitle := ' '
      if x < utf8.RuneCountInString(titleSlice[y]) {
        charTitle = []rune(titleSlice[y])[x]
      }
      termbox.SetCell(x, y, charTitle, termbox.ColorDefault |
        termbox.AttrBold, termbox.ColorDefault)
    }
    for y := range contentSlice[top:] {
      if y < h - 2 - len(optionsSlice) - len(titleSlice) {
        charContent := ' '
        if x < utf8.RuneCountInString(contentSlice[y + top]) {
          charContent = []rune(contentSlice[y + top])[x]
        }
        termbox.SetCell(x, y + 1 + len(titleSlice), charContent,
          termbox.ColorDefault, termbox.ColorDefault)
      }
    }
    for y := range optionsSlice {
      charOptions := ' '
      if x < utf8.RuneCountInString(optionsSlice[y]) {
        charOptions = []rune(optionsSlice[y])[x]
      }
      termbox.SetCell(x, h - 1 - (len(optionsSlice) - y), charOptions,
        termbox.ColorWhite | termbox.AttrBold, termbox.ColorBlue)
    }
    termbox.SetCell(x, len(titleSlice), charLocation, termbox.ColorWhite |
      termbox.AttrBold, termbox.ColorBlue)
    termbox.SetCell(x, h - 1, charBottomCaption, termbox.ColorDefault |
      termbox.AttrBold, termbox.ColorDefault)
  }
  edit_box.Layout(len(bottomCaption), h - 1, w - len(bottomCaption), 1)
  termbox.Flush()
}

/*
 * Returns a string slice with each value being a single line to draw.
 * Uses w to figure out how to split up valueString.
 */
func multiLine(valueString string, w int) []string {
  var counter int
  var valueBuffer string
  var valueSlice []string
  valueString = strings.Replace(valueString, "\r\n", "\n", -1)
  valueString = strings.Replace(valueString, "\n", " \n ", -1)
  valueString = strings.Replace(valueString, "\t", " ", -1)
  valueSplit := strings.Split(valueString, " ")
  if len(valueSplit) > 0 {
    for x := range valueSplit {
      valueSplitTmp := valueSplit[x]
      valueSplit[x] = ""
      for _, runeValue := range valueSplitTmp {
        valueSplit[x] += string(runeValue)
        if runewidth.RuneWidth(runeValue) == 2 {
          valueSplit[x] += " "
        }
      }
      if valueSplit[x] == "\n" {
        valueSlice = append(valueSlice, valueBuffer)
        valueBuffer = ""
        counter = 0
      } else if counter + utf8.RuneCountInString(valueSplit[x]) <= w {
        if counter == 0 && valueSplit[x] == "" {
          select {
          default:
          }
        } else {
          valueBuffer += valueSplit[x]
          counter += utf8.RuneCountInString(valueSplit[x])
          if counter + 1 <= w {
            valueBuffer += " "
            counter += 1
          }
        }
      } else if valueSplit[x] != "" {
        if utf8.RuneCountInString(valueBuffer) > 0 {
          valueSlice = append(valueSlice, valueBuffer)
        }
        valueBuffer = ""
        counter = 0
        modifiedX := valueSplit[x]
        for utf8.RuneCountInString(modifiedX) > w {
          valueSlice = append(valueSlice, string(
            []rune(modifiedX)[:w]))
          modifiedX = string([]rune(modifiedX)[w:])
        }
        if utf8.RuneCountInString(modifiedX) <= w {
          valueBuffer += modifiedX
          counter += utf8.RuneCountInString(modifiedX)
          if counter + 1 <= w {
            valueBuffer += " "
            counter += 1
          }
        }
      }
    }
    if utf8.RuneCountInString(valueBuffer) > 0 {
      valueSlice = append(valueSlice, valueBuffer)
    }
  }
  return valueSlice
}

/*
 * Remove last x values of menuList and make menu equal the new last value of
 * menuList.
 */
func subtractFromMenu(x int) {
  menuList = menuList[:len(menuList) - x]
  menu = menuList[len(menuList) - 1]
}

/* Make menu equal menuString and append menu to menuList. */
func addToMenu(menuString string) {
  menu = menuString
  menuList = append(menuList, menu)
}

/* WELCOME TO LATCHBOX */
func welcomeSettings() {
  ctrlC = false
  termbox.HideCursor()
  locationTitle = "WELCOME TO LATCHBOX"
  options = "n:NEW  o:OPEN"
  contentString = ""
}

func welcomeOptions(ev termbox.Event) {
  if ev.Ch != 0 {
    if ev.Ch == 'n' {
      addToMenu("New Password")
    } else if ev.Ch == 'o' {
      addToMenu("Open Password")
    }
  }
}

/* NEW PASSWORD FILE */
func newPSettings() {
  ctrlC = true
  passwordInput = false
  locationTitle = "NEW PASSWORD FILE"
  options = "Enter:CONFIRM"
  bottomCaption = "Path for New Password File: "
  termbox.SetCursor(len(bottomCaption) + edit_box.CursorX(), h - 1)
  tmpDefault = defaultFile
  if defaultFile != "" {
    tildeHome(&defaultFile)
    if _, err := os.Stat(defaultFile); err == nil {
      contents, err := ioutil.ReadFile(defaultFile)
      if err == nil && string(contents) == "" {
        contentString = "Press Enter to Use " + defaultFile
      } else {
        tmpDefault = ""
      }
    } else {
      contentString = "Press Enter to Use " + defaultFile
    }
  }
  if tmpDefault != "" && contentExtra != "" {
    contentString += "\n\n"
  }
  if contentExtra != "" {
    contentString += contentExtra
  }
}

func newPOptions(ev termbox.Event) {
  contentString = ""
  var valueEntered bool
  if ev.Key == termbox.KeyEnter {
    value = string(edit_box.text)
    valueEntered = true
    edit_box.text = make([]byte, 0)
    edit_box.MoveCursorTo(0)
  } else {
    textEdit(ev)
  }
  if valueEntered {
    if value == "" && tmpDefault != "" {
      value = defaultFile
    }
    if value != "" {
      if _, err := os.Stat(value); err == nil {
        contents, err := ioutil.ReadFile(value)
        if err != nil {
          contentExtra = "Unable to Read File"
        } else if string(contents) == "" {
          fPath = value
        } else {
          contentExtra = "Contents Exist in File"
        }
      } else {
        err := ioutil.WriteFile(value, []byte(""), 0644)
        if err != nil {
          contentExtra = "Unable to Write to File"
        } else {
          os.Remove(value)
          fPath = value
        }
      }
      if fPath != "" {
        step[0] = true
        omit = true
        addToMenu("Secure Password")
      }
    } else {
      contentExtra = "File Name Required"
    }
  }
}

/* SECURE NEW PASSWORD FILE */
func securePSettings() {
  ctrlC = true
  passwordInput = true
  locationTitle = "SECURE NEW PASSWORD FILE"
  options = "Enter:CONFIRM  Ctrl-T:"
  if step[0] {
    bottomCaption = "Input New Passphrase: "
  } else {
    bottomCaption = "Repeat New Passphrase: "
  }
  if omit {
    options += "INCLUDE"
  } else {
    options += "OMIT"
  }
  options += " KEYFILE"
  termbox.SetCursor(len(bottomCaption) + edit_box.CursorX(), h - 1)
}

func securePOptions(ev termbox.Event) {
  var valueEntered bool
  if ev.Key == termbox.KeyEnter {
    value = string(edit_box.text)
    valueEntered = true
    edit_box.text = make([]byte, 0)
    edit_box.MoveCursorTo(0)
  } else if ev.Key == termbox.KeyCtrlT {
    if omit {
      omit = false
    } else {
      omit = true
    }
  } else {
    textEdit(ev)
  }
  if valueEntered {
    if step[0] {
      key1 = value
      contentString = ""
      step[0] = false
    } else {
      if value == key1 {
        if !omit {
          tmpPassphrase = value
          addToMenu("Keyfile")
        } else {
          passphrase = value
          err := writeData()
          if err != nil {
            contentString = "Unable to Create Password File"
          } else {
            contentString = "Your Password File Was Created " +
              "Successfully!"
            addToMenu("Main Menu")
          }
        }
      } else {
        contentString = "New Passphrases Do Not Match"
        step[0] = true
      }
      key1 = ""
    }
  }
}

/* OPEN PASSWORD FILE */
func openPSettings() {
  contentString = ""
  ctrlC = true
  passwordInput = false
  locationTitle = "OPEN PASSWORD FILE"
  options = "Enter:CONFIRM"
  bottomCaption = "Path to Password File: "
  termbox.SetCursor(len(bottomCaption) + edit_box.CursorX(), h - 1)
  tmpDefault = defaultFile
  if defaultFile != "" {
    tildeHome(&defaultFile)
    ciphertext, err := ioutil.ReadFile(defaultFile)
    if backup {
      backupContents = ciphertext
    }
    if err != nil {
      tmpDefault = ""
    } else {
      _, _, _, err := parseCt(ciphertext)
      if err != nil {
        tmpDefault = ""
      } else {
        contentString = "Press Enter to Use " + defaultFile
      }
    }
  }
  if tmpDefault != "" && contentExtra != "" {
    contentString += "\n\n"
  }
  if contentExtra != "" {
    contentString += contentExtra
  }
}

func openPOptions(ev termbox.Event) {
  var valueEntered bool
  if ev.Key == termbox.KeyEnter {
    value = string(edit_box.text)
    valueEntered = true
    edit_box.text = make([]byte, 0)
    edit_box.MoveCursorTo(0)
  } else {
    textEdit(ev)
  }
  if valueEntered {
    if value == "" {
      if tmpDefault != "" {
        value = defaultFile
      } else {
        contentExtra = "Enter File Name"
      }
    }
    tildeHome(&value)
    ciphertext, err := ioutil.ReadFile(value)
    if err != nil {
      contentExtra = "Unable to Read File \"" + value + "\""
    } else {
      _, _, _, err := parseCt(ciphertext)
      if err != nil {
        contentExtra = "Password File Invalid/Corrupted"
      } else {
        fPath = value
        step[0] = true
        contentString = ""
        omit = true
        addToMenu("Unlock Password")
      }
    }
  }
}

/* UNLOCK PASSWORD FILE */
func unlockPSettings() {
  ctrlC = true
  passwordInput = true
  bottomCaption = "Input Passphrase: "
  locationTitle = "UNLOCK PASSWORD FILE"
  options = "Enter:CONFIRM  Ctrl-T:"
  if omit {
    options += "INCLUDE"
  } else {
    options += "OMIT"
  }
  options += " KEYFILE"
  termbox.SetCursor(len(bottomCaption) + edit_box.CursorX(), h - 1)
}

func unlockPOptions(ev termbox.Event) {
  ciphertext, _ := ioutil.ReadFile(fPath)
  var valueEntered bool
  if ev.Key == termbox.KeyEnter {
    value = string(edit_box.text)
    valueEntered = true
    edit_box.text = make([]byte, 0)
    edit_box.MoveCursorTo(0)
  } else if ev.Key == termbox.KeyCtrlT {
    if omit {
      omit = false
    } else {
      omit = true
    }
  } else {
    textEdit(ev)
  }
  if valueEntered {
    if !omit {
      tmpPassphrase = value
      addToMenu("Keyfile")
    } else {
      salt, strippedCtext, hash, _ := parseCt(ciphertext)
      hashedPassphrase := hashKey(value, string(salt))
      plaintext := decrypt(strippedCtext, hashedPassphrase)
      hashPt := sha512.New()
      hashPt.Write(plaintext)
      ptHash := hashPt.Sum(nil)
      if string(hash) == string(ptHash) {
        passphrase = value
        fileContents = plaintext
        err := parseFile()
        if err == nil {
          contentString = ""
          addToMenu("Main Menu")
        }
      } else {
        // Start of Legacy hashKey handling.  To be eventually removed.
        hashedPassphraseLegacy := hashKeyLegacy(value, string(salt))
        plaintextLegacy := decrypt(strippedCtext, hashedPassphraseLegacy)
        hashPtLegacy := sha512.New()
        hashPtLegacy.Write(plaintext)
        ptHashLegacy := hashPt.Sum(nil)
        if string(hash) == string(ptHashLegacy) {
          passphrase = value
          fileContents = plaintextLegacy
          err := parseFile()
          if err == nil {
            contentString = ""
            addToMenu("Main Menu")
          }
        } else {
        // End of Legacy hashKey handling.  To be eventually removed.
          // Move back 2 spaces when Legacy hashKey handling is removed 
          contentString = "Incorrect Passphrase/Keyfile Combination"
        } // Remove extra curly brace when Legacy hashKey handling removed.
      }
    }
  }
}

/* If INCLUDE KEYFILE was selected. */
func keyfileSettings() {
  ctrlC = true
  passwordInput = false
  bottomCaption = "Path to Keyfile: "
  options = "Enter:CONFIRM"
  termbox.SetCursor(len(bottomCaption) + edit_box.CursorX(), h - 1)
}

/*
 * Allows keyfile to be included.  If included, the file's contents will
 * be hashed with SHA512 and appended to the passphrase before hashing
 * the key (passphrase) for encryption/decryption of the password file.
 */
func keyfileOptions(ev termbox.Event) {
  var valueEntered bool
  if ev.Key == termbox.KeyEnter {
    value = string(edit_box.text)
    valueEntered = true
    edit_box.text = make([]byte, 0)
    edit_box.MoveCursorTo(0)
  } else {
    textEdit(ev)
  }
  if valueEntered {
    keyfileContent, err := addKeyFile(value)
    if err != nil {
      contentString = "Cannot Open Keyfile"
    } else {
      hashContent := sha512.New()
      hashContent.Write(keyfileContent)
      contentHash := hashContent.Sum(nil)
      tmpPassphrase += string(contentHash)
      if menuList[len(menuList) - 2] == "Secure Password" {
        passphrase = tmpPassphrase
        err := writeData()
        if err != nil {
          contentString = "Unable to Create Password File"
        } else {
          contentString = "Your Password File Was Created " +
            "Successfully!"
          addToMenu("Main Menu")
        }
        tmpPassphrase = ""
      } else if menuList[len(menuList) - 2] == "Unlock Password" {
        ciphertext, _ := ioutil.ReadFile(fPath)
        salt, strippedCtext, hash, _ := parseCt(ciphertext)
        hashedPassphrase := hashKey(tmpPassphrase, string(salt))
        plaintext := decrypt(strippedCtext, hashedPassphrase)
        hashPt := sha512.New()
        hashPt.Write(plaintext)
        ptHash := hashPt.Sum(nil)
        if string(hash) == string(ptHash) {
          passphrase = tmpPassphrase
          fileContents = plaintext
          err := parseFile()
          if err == nil {
            contentString = ""
            tmpPassphrase = ""
            addToMenu("Main Menu")
          }
        } else {
          // Start of Legacy hashKey handling.  To be eventually removed.
          hashedPassphraseLegacy := hashKeyLegacy(tmpPassphrase, string(salt))
          plaintextLegacy := decrypt(strippedCtext, hashedPassphraseLegacy)
          hashPt := sha512.New()
          hashPt.Write(plaintext)
          ptHashLegacy := hashPt.Sum(nil)
          if string(hash) == string(ptHashLegacy) {
            passphrase = tmpPassphrase
            fileContents = plaintextLegacy
            err := parseFile()
            if err == nil {
              contentString = ""
              tmpPassphrase = ""
              addToMenu("Main Menu")
            }
          } else {
          // End of Legacy hashKey handling.  To be eventually removed.
            // Move allback 2 spaces when Legacy hashKey handling is removed 
            contentString = "Incorrect Passphrase/Keyfile " +
              "Combination"
            tmpPassphrase = ""
            omit = true
            subtractFromMenu(1)
          } // Remove extra curly brace when Legacy hashKey handling removed.
        }
      } else if menuList[len(menuList) - 2] == "Export" {
        if passphrase == tmpPassphrase {
          contentString = ""
          tmpPassphrase = ""
          omit = true
          err := exportCSV(csvFile)
          if err != nil {
            contentString = "Unable to Create " + csvFile
            step[0] = true
          } else {
            contentString = "Exported Succesfully to " + csvFile
            subtractFromMenu(1)
          }
          csvFile = ""
          subtractFromMenu(1)
        } else {
          contentString = "Incorrect Passphrase/Keyfile " +
            "Combination"
          tmpPassphrase = ""
          omit = true
          subtractFromMenu(1)
        }
      } else {
        if step[0] {
          if passphrase == tmpPassphrase {
            contentString = ""
            step[0], step[1] = false, true
            tmpPassphrase = ""
            omit = true
            subtractFromMenu(1)
          } else {
            contentString = "Incorrect Passphrase/Keyfile " +
              "Combination"
            tmpPassphrase = ""
            omit = true
            subtractFromMenu(1)
          }
        } else {
          passphrase = tmpPassphrase
          err := writeData()
          if err != nil {
            contentString = "Unable to Modify Password File " +
              "(Write Error)"
          } else {
            contentString = "Your Passphrase/Keyfile Was " +
              "Successfully Changed!"
            addToMenu("Main Menu")
          }
          tmpPassphrase = ""
        }
      }
    }
  }
}

/*
 * Get Content of filePath for the keyFile to help decrypt the password
 * file.
 */
func addKeyFile(filePath string) ([]byte, error) {
  tildeHome(&filePath);
  content, err := ioutil.ReadFile(filePath)
  if err != nil {
    return nil, err
  }
  return content, nil
}

/* MAIN MENU */
func mainSettings() {
  ctrlC = false
  termbox.HideCursor()
  bottomCaption = ""
  locationTitle = "MAIN MENU"
  if len(names) > 0 {
    options = "c:COPY  v:VIEW  n:NEW  d:DELETE  e:EDIT  l:LOCK  " +
      "?:MORE OPTIONS"
  } else {
    options = "n:NEW  l:LOCK  ?:MORE OPTIONS"
  }
}

func mainOptions(ev termbox.Event) {
  if ev.Ch != 0 {
    if len(names) > 0 {
      if ev.Ch == 'c' {
        addToMenu("Copy")
      } else if ev.Ch == 'v' {
        addToMenu("View")
      } else if ev.Ch == 'd' {
        addToMenu("Delete")
      } else if ev.Ch == 'e' {
        step[0] = true
        addToMenu("Edit")
      }
    }
    if ev.Ch == 'n' {
      step[0] = true
      addToMenu("New")
    } else if ev.Ch == 'l' {
      lock()
    } else if ev.Ch == 'p' {
      addToMenu("Change Passphrase")
    } else if ev.Ch == 'i' {
      contentString = ""
      addToMenu("Import")
    } else if ev.Ch == 'x' {
      contentString = ""
      step[0] = true
      omit = true
      addToMenu("Export")
    } else if ev.Ch == '?' {
      addToMenu("Options")
    }
  }
}

/* COPY ENTRY (first menu) */
func copyESettings() {
  ctrlC = true
  passwordInput = false
  locationTitle = "COPY ENTRY"
  options = "Enter:CONFIRM"
  bottomCaption = "Input Entry Number: "
  contentString = displayNameGroups()
  termbox.SetCursor(len(bottomCaption) + edit_box.CursorX(), h - 1)
}

func copyEOptions(ev termbox.Event) {
  var valueEntered bool
  entryNumber = 0
  if ev.Key == termbox.KeyEnter {
    value = string(edit_box.text)
    valueEntered = true
    edit_box.text = make([]byte, 0)
    edit_box.MoveCursorTo(0)
  } else {
    textEdit(ev)
  }
  if valueEntered {
    intVal, err := strconv.Atoi(value)
    if err == nil {
      if intVal > 0 && intVal <= len(names) {
        entryNumber = intVal
        entryData = ""
        addToMenu("Copy Content")
      }
    }
  }
}

/* COPY ENTRY (second menu) */
func copyContentSettings() {
  ctrlC = true
  termbox.HideCursor()
  bottomCaption = ""
  if entryData == "" {
    contentString = "Choose What You Want to Copy"
    options = "u:USERNAME  p:PASSWORD  e:EMAIL  w:URL"
  } else {
    contentString = entryData  + " Copied.  Press Ctrl-C to Clear the " +
      "Clipboard"
    options = "Ctrl-C:CLEAR CLIPBOARD/BACK"
    contentCopied = true
  }
}

func copyContentOptions(ev termbox.Event) {
  if entryData == "" {
    if ev.Ch != 0 {
      if ev.Ch == 'u' {
        entryData = "Username"
      } else if ev.Ch == 'p' {
        entryData = "Password"
      } else if ev.Ch == 'e' {
        entryData = "Email"
      } else if ev.Ch == 'w' {
        entryData = "URL"
      }
    }
    if entryData != "" {
      var data string
      if entryData == "Username" {
        data = usernames[orderList[entryNumber - 1]]
      } else if entryData == "Password" {
        data = passwords[orderList[entryNumber - 1]]
      } else if entryData == "Email" {
        data = emails[orderList[entryNumber - 1]]
      } else if entryData == "URL" {
        data = urls[orderList[entryNumber - 1]]
      }
      err := clipboard.WriteAll(data)
      if err != nil {
        subtractFromMenu(2)
        contentString = "Unable to Copy Content to Clipboard"
      }
    }
  }
}

/* VIEW ENTRY (first menu) */
func viewESettings() {
  ctrlC = true
  passwordInput = false
  locationTitle = "VIEW ENTRY"
  options = "Enter:CONFIRM"
  bottomCaption = "Input Entry Number: "
  contentString = displayNameGroups()
  termbox.SetCursor(len(bottomCaption) + edit_box.CursorX(), h - 1)
}

func viewEOptions(ev termbox.Event) {
  var valueEntered bool
  entryNumber = 0
  if ev.Key == termbox.KeyEnter {
    value = string(edit_box.text)
    valueEntered = true
    edit_box.text = make([]byte, 0)
    edit_box.MoveCursorTo(0)
  } else {
    textEdit(ev)
  }
  if valueEntered {
    intVal, err := strconv.Atoi(value)
    if err == nil {
      if intVal > 0 && intVal <= len(names) {
        entryNumber = intVal
        show = false
        addToMenu("View Content")
      }
    }
  }
}

/* VIEW ENTRY (second menu) */
func viewContentSettings() {
  ctrlC = true
  termbox.HideCursor()
  bottomCaption = ""
  var password string
  name := names[orderList[entryNumber - 1]]
  username := usernames[orderList[entryNumber - 1]]
  if show {
    password = passwords[orderList[entryNumber - 1]]
    options = "s:HIDE PASSWORD"
  } else {
    for _ = range passwords[orderList[entryNumber - 1]] {
      password += "*"
    }
    options = "s:SHOW PASSWORD"
  }
  email := emails[orderList[entryNumber - 1]]
  url := urls[orderList[entryNumber - 1]]
  group := groups[orderList[entryNumber - 1]]
  comment := comments[orderList[entryNumber - 1]]
  made := created[orderList[entryNumber - 1]]
  edited := modified[orderList[entryNumber - 1]]
  contentString = "Name: " + name + "\n"
  contentString += "Username: " + username + "\n"
  contentString += "Password: " + password + "\n"
  contentString += "Email: " + email + "\n"
  contentString += "URL: " + url + "\n"
  contentString += "Group: " + group + "\n"
  contentString += "Comment: " + comment + "\n\n"
  contentString += "Created: " + made + "\n"
  contentString += "Modified: " + edited + "\n"
}

func viewContentOptions(ev termbox.Event) {
  if ev.Ch != 0 {
    if ev.Ch == 's' {
      if show {
        show = false
      } else {
        show = true
      }
    }
  }
}

/* NEW ENTRY */
func newESettings() {
  ctrlC = true
  passwordInput = false
  locationTitle = "NEW ENTRY"
  options = "Enter:CONFIRM"
  if step[0] {
    contentString = "Input New Name (Required)"
    bottomCaption = "Input New Name: "
  } else if step[1] {
    contentString = "Input New Username"
    bottomCaption = "Input New Username: "
  } else if step[2] {
    contentString = "Generate Password?"
  } else if step[3] {
    contentString = "Input Password Length"
    bottomCaption = "Input Password Length: "
  } else if step[4] {
    contentString = "Include Uppercase Letters In Password?"
  } else if step[5] {
    contentString = "Include Lowercase Letters In Password?"
  } else if step[6] {
    contentString = "Include Numbers In Password?"
  } else if step[7] {
    contentString = "Include Symbols In Password?"
  } else if step[8] {
    contentString = "Input New Password"
    bottomCaption = "Input New Password: "
  } else if step[9] {
    contentString = "Repeat New Password"
    bottomCaption = "Repeat New Password: "
  } else if step[10] {
    contentString = "Input New Email"
    bottomCaption = "Input New Email: "
  } else if step[11] {
    contentString = "Input New URL"
    bottomCaption = "Input New URL: "
  } else if step[12] {
    contentString = "Input New Group"
    bottomCaption = "Input New Group: "
  } else {
    contentString = "Input New Comment"
    bottomCaption = "Input New Comment: "
  }
  if step[8] || step[9] {
    passwordInput = true
  } else {
    passwordInput = false
  }
  if step[2] || step[4] || step[5] || step[6] || step[7] {
    options = "y:YES  n:NO"
    bottomCaption = ""
    termbox.HideCursor()
  } else {
    termbox.SetCursor(len(bottomCaption) + edit_box.CursorX(), h - 1)
  }
  if len(contentExtra) > 1 {
    contentString += "\n\n" + contentExtra
  }
}

func newEOptions(ev termbox.Event) {
  var valueEntered bool
  entryNumber = 0
  if !step[2] && !step[4] && !step[5] && !step[6] && !step[7] {
    if ev.Key == termbox.KeyEnter {
      value = string(edit_box.text)
      valueEntered = true
      edit_box.text = make([]byte, 0)
      edit_box.MoveCursorTo(0)
    } else {
      textEdit(ev)
    }
    if valueEntered {
      if step[0] {
        newValue = make([]string, 0)
        if len(value) < 256 && len(value) > 0 {
          if !inString(value, "/") &&
            !inString(value, "\\") {
            contentExtra = ""
            newValue = append(newValue, value)
            step[0], step[1] = false, true
          } else {
            contentExtra = "Invalid Character \"/\""
          }
        } else if len(value) == 0 {
          contentExtra = "Name Required"
        } else {
          contentExtra = "Name Too Long"
        }
      } else if step[1] {
        if len(value) < 256 {
          contentExtra = ""
          newValue = append(newValue, value)
          step[1], step[2] = false, true
        } else {
          contentExtra = "Username Too Long"
        }
      } else if step[3] {
        passLen = 0
        passLenInt, err := strconv.Atoi(value)
        if err != nil {
          contentExtra = "Password Length Must be an Integer"
        } else {
          if passLenInt > 3 && passLenInt < 65536 {
            contentExtra = ""
            passLen = passLenInt
            step[3], step[4] = false, true
          } else {
            contentExtra = "Password Length Must be Between 4 " +
              "and 65536"
          }
        }
      } else if step[8] {
        key1 = ""
        if len(value) < 65536 {
          contentExtra = ""
          key1 = value
          step[8], step[9] = false, true
        } else if len(value) <= 4 {
          contentExtra = "Password Too Short"
        } else {
          contentExtra = "Password Too Long"
        }
      } else if step[9] {
        if value == key1 {
          contentExtra = ""
          newValue = append(newValue, value)
          step[9], step[10] = false, true
        } else {
          contentExtra = "New Passwords Do Not Match"
          step[9], step[8] = false, true
        }
      } else if step[10] {
        if len(value) < 256 {
          contentExtra = ""
          newValue = append(newValue, value)
          step[10], step[11] = false, true
        } else {
          contentExtra = "Email Too Long"
        }
      } else if step[11] {
        if len(value) < 256 {
          contentExtra = ""
          newValue = append(newValue, value)
          step[11], step[12] = false, true
        } else {
          contentExtra = "URL Too Long"
        }
      } else if step[12] {
        if len(value) < 256 {
          nameGroupsList := nameGroups()
          if len(value) > 0 {
            nameGroupsList = append(nameGroupsList, value + "/" +
              newValue[0])
          } else {
            nameGroupsList = append(nameGroupsList, newValue[0])
          }
          if duplicateNameGroups(nameGroupsList) {
            contentExtra = "Duplicate Name/Group Combination " +
              "(Staring Over)"
            newValue = make([]string, 0)
            step[12], step[0] = false, true
          } else {
            if len(value) > 0 {
              if value[0] != '/' && value[len(value) - 1] !=
                  '/' && !inString(value, "//") &&
                  !inString(value, "/ ") &&
                  !inString(value, "\\") {
                contentExtra = ""
                newValue = append(newValue, value)
                step[12] = false
              } else {
                contentExtra = "Invalid Group Name"
              }
            } else {
              contentExtra = ""
              newValue = append(newValue, value)
              step[12] = false
            }
          }
        } else {
          contentExtra = "Group Name Too Long"
        }
      } else {
        if len(value) < 65536 {
          contentExtra = ""
          names = append(names, newValue[0])
          usernames = append(usernames, newValue[1])
          passwords = append(passwords, newValue[2])
          emails = append(emails, newValue[3])
          urls = append(urls, newValue[4])
          groups = append(groups, newValue[5])
          comments = append(comments, value)
          create := time.Now().Format(timeLayout)
          created = append(created, create)
          modified = append(modified, create)
          passChars = make([]bool, 0)
          newValue = make([]string, 0)
          passLen = 0
          err := writeData()
          if err != nil {
            contentString = "Unable to Modify Password File " +
              "(Write Error)"
          } else {
            contentString = ""
          }
          subtractFromMenu(1)
        } else {
          contentExtra = "Comment Too Long"
        }
      }
    }
  } else {
    if ev.Ch == 'y' {
      if step[2] {
        step[2], step[3] = false, true
      } else if step[4] {
        passChars = append(passChars, true)
        step[4], step[5] = false, true
      } else if step[5] {
        passChars = append(passChars, true)
        step[5], step[6] = false, true
      } else if step[6] {
        passChars = append(passChars, true)
        step[6], step[7] = false, true
      } else {
        passChars = append(passChars, true)
        password := genPass(uint16(passLen), passChars)
        newValue = append(newValue, password)
        step[7], step[10] = false, true
      }
    } else if ev.Ch == 'n' {
      if step[2] {
        step[2], step[8] = false, true
      } else if step[4] {
        passChars = append(passChars, false)
        step[4], step[5] = false, true
      } else if step[5] {
        passChars = append(passChars, false)
        step[5], step[6] = false, true
      } else if step[6] {
        passChars = append(passChars, false)
        step[6], step[7] = false, true
      } else {
        passChars = append(passChars, false)
        password := genPass(uint16(passLen), passChars)
        newValue = append(newValue, password)
        step[7], step[10] = false, true
      }
    }
  }
}

/* DELETE ENTRY (first menu) */
func deleteESettings() {
  ctrlC = true
  passwordInput = false
  locationTitle = "DELETE ENTRY"
  options = "Enter:CONFIRM"
  bottomCaption = "Input Entry Number: "
  contentString = displayNameGroups()
  termbox.SetCursor(len(bottomCaption) + edit_box.CursorX(), h - 1)
}

func deleteEOptions(ev termbox.Event) {
  var valueEntered bool
  entryNumber = 0
  if ev.Key == termbox.KeyEnter {
    value = string(edit_box.text)
    valueEntered = true
    edit_box.text = make([]byte, 0)
    edit_box.MoveCursorTo(0)
  } else {
    textEdit(ev)
  }
  if valueEntered {
    intVal, err := strconv.Atoi(value)
    if err == nil {
      if intVal > 0 && intVal <= len(names) {
        entryNumber = intVal
        addToMenu("Delete Content")
      }
    }
  }
}

/* DELETE ENTRY (second menu) */
func deleteContentSettings() {
  ctrlC = true
  termbox.HideCursor()
  bottomCaption = ""
  if menuList[len(menuList) - 2] == "Delete" {
    menuList = append(menuList[:len(menuList) - 2],
      menuList[len(menuList) - 1])
  }
  nameGroupsList := nameGroups()
  contentString = "Are You Sure You Want to Delete " +
    nameGroupsList[entryNumber - 1] + "?"
  options = "y:YES  n:NO"
}

func deleteContentOptions(ev termbox.Event) {
  num := orderList[entryNumber - 1]
  nameGroupsList := nameGroups()
  if ev.Ch != 0 {
    if ev.Ch == 'y' {
      names = append(names[:num], names[num + 1:]...)
      usernames = append(usernames[:num], usernames[num + 1:]...)
      passwords = append(passwords[:num], passwords[num + 1:]...)
      emails = append(emails[:num], emails[num + 1:]...)
      urls = append(urls[:num], urls[num + 1:]...)
      groups = append(groups[:num], groups[num + 1:]...)
      comments = append(comments[:num], comments[num + 1:]...)
      created = append(created[:num], created[num + 1:]...)
      modified = append(modified[:num], modified[num + 1:]...)
      err := writeData()
      if err != nil {
        contentString = "Unable to Modify Password File (Write Error)"
      } else {
        contentString = nameGroupsList[entryNumber - 1] +
          " Was Successfully Deleted"
      }
      subtractFromMenu(1)
    } else if ev.Ch == 'n' {
      contentString = nameGroupsList[entryNumber - 1] +
        " Was NOT Deleted"
      subtractFromMenu(1)
    }
  }
}

/* EDIT ENTRY (first menu) */
func editESettings() {
  ctrlC = true
  passwordInput = false
  locationTitle = "EDIT ENTRY"
  options = "Enter:CONFIRM"
  bottomCaption = "Input Entry Number: "
  contentString = displayNameGroups()
  termbox.SetCursor(len(bottomCaption) + edit_box.CursorX(), h - 1)
}

func editEOptions(ev termbox.Event) {
  var valueEntered bool
  entryNumber = 0
  if ev.Key == termbox.KeyEnter {
    value = string(edit_box.text)
    valueEntered = true
    edit_box.text = make([]byte, 0)
    edit_box.MoveCursorTo(0)
  } else {
    textEdit(ev)
  }
  if valueEntered {
    intVal, err := strconv.Atoi(value)
    if err == nil {
      if intVal > 0 && intVal <= len(names) {
        entryNumber = intVal
        addToMenu("Edit Content")
      }
    }
  }
}

/* EDIT ENTRY (second menu) */
func editContentSettings() {
  ctrlC = true
  termbox.HideCursor()
  if menuList[len(menuList) - 2] == "Edit" {
    menuList = append(menuList[:len(menuList) - 2],
      menuList[len(menuList) - 1])
  }
  bottomCaption = ""
  if entryData == "" {
    nameGroupsList := nameGroups()
    contentString = "Choose What You Want to Edit for " +
      nameGroupsList[entryNumber - 1]
    options = "n:NAME  u:USERNAME  p:PASSWORD  e:EMAIL  w:URL  g:GROUP  " +
      "c:COMMENT"
  } else {
    options = "Enter:CONFIRM"
    if entryData == "Name" {
      contentString = "Input New Name (Required)"
      bottomCaption = "Input New Name: "
    } else if entryData == "Username" {
      contentString = "Input New Username"
      bottomCaption = "Input New Username: "
    } else if entryData == "Password" {
      passwordInput = true
      if step[0] || step[2] || step[3] || step[4] || step[5] {
        contentString = ""
        termbox.HideCursor()
        options = "y:YES  n:NO"
      }
      if step[0] {
        contentString = "Generate Password?"
      } else if step[1] {
        passwordInput = false
        contentString = "Input Password Length"
        bottomCaption = "Input Password Length: "
        termbox.SetCursor(len(bottomCaption) + edit_box.CursorX(),
          h - 1)
      } else if step[2] {
        contentString = "Include Uppercase Letters in Password?"
      } else if step[3] {
        contentString = "Include Lowercase Letters in Password?"
      } else if step[4] {
        contentString = "Include Numbers in Password?"
      } else if step[5] {
        contentString = "Include Symbols in Password?"
      } else if step[6] {
        contentString = "Input New Password"
        bottomCaption = "Input New Password: "
        termbox.SetCursor(len(bottomCaption) + edit_box.CursorX(),
          h - 1)
      } else {
        contentString = "Repeat New Password"
        bottomCaption = "Repeat New Password: "
        termbox.SetCursor(len(bottomCaption) + edit_box.CursorX(),
          h - 1)
      }
    } else if entryData == "Email" {
      contentString = "Input New Email"
      bottomCaption = "Input New Email: "
    } else if entryData == "URL" {
      contentString = "Input New URL"
      bottomCaption = "Input New URL: "
    } else if entryData == "Group" {
      contentString = "Input New Group"
      bottomCaption = "Input New Group: "
    } else if entryData == "Comment" {
      contentString = "Input New Comment"
      bottomCaption = "Input New Comment: "
    }
    if entryData != "Password" {
      passwordInput = false
      termbox.SetCursor(len(bottomCaption) + edit_box.CursorX(), h - 1)
    }
    if len(contentExtra) > 0 {
      contentString += "\n\n" + contentExtra
    }
  }
}

func editContentOptions(ev termbox.Event) {
  var valueEntered bool
  num := orderList[entryNumber - 1]
  nameGroupsList := nameGroups()
  if entryData == "" {
    if ev.Ch != 0 {
      if ev.Ch == 'n' {
        entryData = "Name"
      } else if ev.Ch == 'u' {
        entryData = "Username"
      } else if ev.Ch == 'p' {
        entryData = "Password"
      } else if ev.Ch == 'e' {
        entryData = "Email"
      } else if ev.Ch == 'w' {
        entryData = "URL"
      } else if ev.Ch == 'g' {
        entryData = "Group"
      } else if ev.Ch == 'c' {
        entryData = "Comment"
      }
    }
  } else if entryData == "Password" {
    if step[0] || step[2] || step[3] || step[4] || step[5] {
      if ev.Ch == 'y' {
        contentExtra = ""
        if step[0] {
          step[0], step[1] = false, true
        } else if step[2] {
          passChars = append(passChars, true)
          step[2], step[3] = false, true
        } else if step[3] {
          passChars = append(passChars, true)
          step[3], step[4] = false, true
        } else if step[4] {
          passChars = append(passChars, true)
          step[4], step[5] = false, true
        } else {
          contentString = "Password Changed"
          passChars = append(passChars, true)
          password := genPass(uint16(passLen), passChars)
          passwords[num] = password
          subtractFromMenu(1)
          step[5] = false
        }
      } else if ev.Ch == 'n' {
        contentExtra = ""
        if step[0] {
          step[0], step[6] = false, true
        } else if step[2] {
          passChars = append(passChars, false)
          step[2], step[3] = false, true
        } else if step[3] {
          passChars = append(passChars, false)
          step[3], step[4] = false, true
        } else if step[4] {
          passChars = append(passChars, false)
          step[4], step[5] = false, true
        } else {
          contentString = "Password Changed"
          passChars = append(passChars, false)
          password := genPass(uint16(passLen), passChars)
          passwords[num] = password
          subtractFromMenu(1)
          step[5] = false
        }
      }
    } else {
      if ev.Key == termbox.KeyEnter {
        value = string(edit_box.text)
        valueEntered = true
        edit_box.text = make([]byte, 0)
        edit_box.MoveCursorTo(0)
      } else {
        textEdit(ev)
      }
      if valueEntered {
        if step[1] {
          passLen = 0
          passLenInt, err := strconv.Atoi(value)
          if err == nil {
            if passLenInt > 3 && passLenInt < 65536 {
              contentExtra = ""
              passLen = passLenInt
              step[1], step[2] = false, true
            } else {
              contentExtra = "Password Length Must be " +
                "Between 4 and 65536"
            }
          } else {
            contentExtra = "Password Length Must be an Integer"
          }
        } else if step[6] {
          key1 = ""
          if len(value) < 65536 {
            contentExtra = ""
            key1 = value
            step[6], step[7] = false, true
          } else if len(value) <= 4 {
            contentExtra = "Password Too Short"
          } else {
            contentExtra = "Password Too Long"
          }
        } else {
          if key1 == value {
            contentString = "Password Changed"
            passwords[num] = value
            subtractFromMenu(1)
            step[5] = false
          } else {
            contentExtra = "New Passwords Do Not Match"
          }
        }
      }
    }
  } else {
    if ev.Key == termbox.KeyEnter {
      value = string(edit_box.text)
      valueEntered = true
      edit_box.text = make([]byte, 0)
      edit_box.MoveCursorTo(0)
    } else {
      textEdit(ev)
    }
    if valueEntered {
      contentExtra = ""
      if entryData == "Name" {
        if len(value) < 256 && len(value) > 0 &&
            !inString(value, "/") &&
            !inString(value, "\\") {
          name := value
          group := groups[entryNumber - 1]
          if group == "" {
            nameGroupsList[entryNumber - 1] = name
          } else {
            nameGroupsList[entryNumber - 1] = group +
              "/" + name
          }
          if !duplicateNameGroups(nameGroupsList) {
            contentString = "Name Changed"
            names[num] = value
            subtractFromMenu(1)
          } else {
            contentExtra = "Duplicate Name/Group Combination"
          }
        } else if len(value) == 0 {
          contentExtra = "Name Required"
        } else if len(value) > 256 {
          contentExtra = "Name Too Long"
        } else {
          contentExtra = "Invalid Character \"/\""
        }
      } else if entryData == "Username" {
        if len(value) < 256 {
          contentString = "Username Changed"
          usernames[num] = value
          subtractFromMenu(1)
        } else {
          contentExtra = "Username Too Long"
        }
      } else if entryData == "Email" {
        if len(value) < 256 {
          contentString = "Email Changed"
          emails[num] = value
          subtractFromMenu(1)
        }
      } else if entryData == "URL" {
        if len(value) < 256 {
          contentString = "URL Changed"
          urls[num] = value
          subtractFromMenu(1)
        }
      } else if entryData == "Group" {
        if len(value) < 256{
          group := value
          name := names[num]
          if group == "" {
            nameGroupsList[entryNumber - 1] = name
          } else {
            nameGroupsList[entryNumber - 1] = group +
              "/" + name
          }
          if group[0] != '/' && group[len(group) - 1] != '/' &&
              !inString(group, "//") && !inString(group, "/ ") &&
              !inString(group, "\\") {
            if !duplicateNameGroups(nameGroupsList) {
              contentString = "Group Name Changed"
              groups[num] = value
              subtractFromMenu(1)
            } else {
              contentExtra = "Duplicate Name/Group Combination"
            }
          } else {
            contentExtra = "Invalid Group Name"
          }
        } else {
          contentExtra = "Group Name Too Long"
        }
      } else if entryData == "Comment" {
        if len(value) < 65536 {
          contentString = "Comment Changed"
          comments[num] = value
          subtractFromMenu(1)
        }
      }
    }
  }
  if menu == "Main Menu" {
    contentExtra = ""
    entryData = ""
    modified[num] = time.Now().Format(timeLayout)
    err := writeData()
    if err != nil  {
      contentString = "Unable to Modify Password File (Write Error)"
    }
  }
}

/* CHANGE PASSPHRASE/KEYFILE (first menu) */
func cPassphraseSettings() {
  ctrlC = true
  termbox.HideCursor()
  locationTitle = "CHANGE PASSPHRASE/KEYFILE"
  contentString = ""
  options = "y:YES  n:NO"
}

func cPassphraseOptions(ev termbox.Event) {
  if ev.Ch == 'y' {
    omit = true
    step[0] = true
    addToMenu("Passphrase")
  } else if ev.Ch == 'n' {
    subtractFromMenu(1)
  }
}

/* CHANGE PASSPHRASE/KEYFILE (second menu) */
func passphraseSettings() {
  if menuList[len(menuList) - 2] == "Change Passphrase" {
    menuList = append(menuList[:len(menuList) - 2],
      menuList[len(menuList) - 1])
  }
  ctrlC = true
  passwordInput = true
  contentString = ""
  options = "Enter:CONFIRM  Ctrl-T:"
  if step[0] {
    bottomCaption = "Input Passphrase: "
  } else if step[1] {
    bottomCaption = "Input New Password: "
  } else {
    bottomCaption = "Repeat New Password: "
  }
  if omit {
    options += "INCLUDE"
  } else {
    options += "OMIT"
  }
  options += " KEYFILE"
  termbox.SetCursor(len(bottomCaption) + edit_box.CursorX(), h - 1)
}

func passphraseOptions(ev termbox.Event) {
  var valueEntered bool
  if ev.Key == termbox.KeyEnter {
    value = string(edit_box.text)
    valueEntered = true
    edit_box.text = make([]byte, 0)
    edit_box.MoveCursorTo(0)
  } else if ev.Key == termbox.KeyCtrlT {
    if omit {
      omit = false
    } else {
      omit = true
    }
  } else {
    textEdit(ev)
  }
  if valueEntered {
    if step[0] {
      if !omit {
        contentString = ""
        tmpPassphrase = value
        addToMenu("Keyfile")
      } else {
        if value == passphrase {
          contentString = ""
          step[0], step[1] = false, true
        } else {
          contentString = "Incorrect Passphrase/Keyfile " +
            "Combination"
        }
      }
    } else if step[1] {
      key1 = value
      contentString = ""
      step[1] = false
    } else {
      if value == key1 {
        if !omit {
          tmpPassphrase = value
          addToMenu("Keyfile")
        } else {
          passphrase = value
          err := writeData()
          if err != nil {
            contentString = "Unable to Modify Password File " +
              "(Write Error)"
          } else {
            contentString = "Your Passphrase/Keyfile Was " +
              "Successfully Changed!"
          }
          addToMenu("Main Menu")
        }
      } else {
        contentString = "New Passphrases Do Not Match"
        step[1] = true
      }
      key1 = ""
    }
  }
}

/* IMPORT CSV FILE */
func importSettings() {
  ctrlC = true
  locationTitle = "IMPORT CSV FILE"
  options = "Enter:CONFIRM"
  passwordInput = false
  bottomCaption = "Path for CSV File: "
  termbox.SetCursor(len(bottomCaption) + edit_box.CursorX(), h - 1)
}

func importOptions(ev termbox.Event) {
  var valueEntered bool
  if ev.Key == termbox.KeyEnter {
    value = string(edit_box.text)
    valueEntered = true
    edit_box.text = make([]byte, 0)
    edit_box.MoveCursorTo(0)
  } else {
    textEdit(ev)
  }
  if valueEntered {
    tildeHome(&value)
    if _, err := os.Stat(value); err != nil {
      contentString = "File " + value + " Does Not Exist"
    } else {
      namesBackup := names[:]
      usernamesBackup := usernames[:]
      passwordsBackup := passwords[:]
      emailsBackup := emails[:]
      urlsBackup := urls[:]
      groupsBackup := groups[:]
      commentsBackup := comments[:]
      createdBackup := created[:]
      modifiedBackup := modified[:]
      err := importCSV(value)
      if err != nil {
        names = namesBackup[:]
        usernames = usernamesBackup[:]
        passwords = passwordsBackup[:]
        emails = emailsBackup[:]
        urls = urlsBackup[:]
        groups = groupsBackup[:]
        comments = commentsBackup[:]
        created = createdBackup[:]
        modified = modifiedBackup[:]
      }
      subtractFromMenu(1)
    }
  }
}

/* EXPORT CSV FILE */
func exportSettings() {
  ctrlC = true
  locationTitle = "EXPORT CSV FILE"
  options = "Enter:CONFIRM"
  if step[0] {
    passwordInput = false
    bottomCaption = "Path for CSV File: "
  } else {
    passwordInput = true
    bottomCaption = "Input Passphrase: "
    options += "  Ctrl-T:"
    if omit {
      options += "INCLUDE"
    } else {
      options += "OMIT"
    }
    options += " KEYFILE"
  }
  termbox.SetCursor(len(bottomCaption) + edit_box.CursorX(), h - 1)
}

func exportOptions(ev termbox.Event) {
  var valueEntered bool
  if ev.Key == termbox.KeyEnter {
    value = string(edit_box.text)
    valueEntered = true
    edit_box.text = make([]byte, 0)
    edit_box.MoveCursorTo(0)
  } else if ev.Key == termbox.KeyCtrlT && !step[0] {
    if omit {
      omit = false
    } else {
      omit = true
    }
  } else {
    textEdit(ev)
  }
  if valueEntered {
    tildeHome(&value)
    if step[0] {
      if _, err := os.Stat(value); err == nil {
        contentString = "File " + value + " Already Exists"
      } else {
        contentString = ""
        csvFile = value
        step[0] = false
      }
    } else {
      if !omit {
        contentString = ""
        tmpPassphrase = value
        addToMenu("Keyfile")
      } else {
        if value == passphrase {
          contentString = ""
          err := exportCSV(csvFile)
          if err != nil {
            contentString = "Unable to Create " + csvFile
            step[0] = true
          } else {
            subtractFromMenu(1)
          }
          csvFile = ""
        } else {
          contentString = "Incorrect Passphrase/Keyfile " +
            "Combination"
        }
      }
    }
  }
}

/* MORE OPTIONS */
func optionsSettings() {
  ctrlC = true
  termbox.HideCursor()
  locationTitle = "MORE OPTIONS"
  options = "Ctrl-C:BACK"
  bottomCaption = ""
  contentString = "c:COPY          Copy Value of Entry\n\n" +
    "v:VIEW          View Values of Entry\n\n" +
    "n:NEW           Create a New Entry\n\n" +
    "d:DELETE        Delete Entry\n\n" +
    "e:EDIT          Edit Value of Entry\n\n" +
    "p:PASSPHRASE    Change Passphrase/Keyfile of Password File\n\n" +
    "i:IMPORT        Import Entries from .CSV File\n\n" +
    "x:EXPORT        Export Entries to a .CSV File\n\n" +
    "l:LOCK          Lock Password File"
}

func fill(x, y, w, h int, cell termbox.Cell) {
  for ly := 0; ly < h; ly++ {
    for lx := 0; lx < w; lx++ {
      termbox.SetCell(x + lx, y + ly, cell.Ch, cell.Fg, cell.Bg)
    }
  }
}

func voffset_coffset(text []byte, boffset int) (voffset, coffset int) {
  text = text[:boffset]
  for len(text) > 0 {
    rune_at, size := utf8.DecodeRune(text)
    if runewidth.RuneWidth(rune_at) == 2 && !passwordInput {
      coffset += 1
      voffset += 1
    }
    text = text[size:]
    coffset += 1
    voffset += 1
  }
  return
}

func byte_slice_grow(s []byte, desired_cap int) []byte {
  if cap(s) < desired_cap {
    ns := make([]byte, len(s), desired_cap)
    copy(ns, s)
    return ns
  }
  return s
}

func byte_slice_remove(text []byte, from, to int) []byte {
  size := to - from
  copy(text[from:], text[to:])
  text = text[:len(text) - size]
  return text
}

func byte_slice_insert(text []byte, offset int, what []byte) []byte {
  n := len(text) + len(what)
  text = byte_slice_grow(text, n)
  text = text[:n]
  copy(text[offset+len(what):], text[offset:])
  copy(text[offset:], what)
  return text
}

type EditBox struct {
  text []byte
  line_voffset int
  cursor_boffset int
  cursor_voffset int
  cursor_coffset int
}

func (eb *EditBox) Layout(x, y, w, h int) {
  eb.AdjustVOffset(w)
  const coldef = termbox.ColorDefault
  fill(x, y, w, h, termbox.Cell{Ch: ' '})
  t := make([]byte, 0)
  /* Input * characters if passwordInput is true */
  if passwordInput {
    for _ = range string(eb.text) {
      t = append(t, '*')
    }
  } else {
    for index, value := range string(eb.text) {
      t = append(t, eb.text[index: index + utf8.RuneLen(value)]...)
      if runewidth.RuneWidth(value) == 2 {
        t = append(t, ' ')
      }
    }
  }
  lx := 0
  for {
    rx := lx - eb.line_voffset
    if len(t) == 0 {
      break
    }
    if rx >= w {
      break
    }
    r, size := utf8.DecodeRune(t)
    if rx >= 0 {
      termbox.SetCell(x + rx, y, r, coldef, coldef)
    }
    lx += 1
    t = t[size:]
  }
}

func (eb *EditBox) AdjustVOffset(width int) {
  threshold := width - 1
  if eb.line_voffset != 0 {
    threshold = width
  }
  if eb.cursor_voffset - eb.line_voffset >= threshold {
    eb.line_voffset = eb.cursor_voffset - width + 1
  }
  if eb.line_voffset != 0 && eb.cursor_voffset - eb.line_voffset < 0 {
    eb.line_voffset = eb.cursor_voffset
    if eb.line_voffset < 0 {
      eb.line_voffset = 0
    }
  }
}

func (eb *EditBox) MoveCursorTo(boffset int) {
  eb.cursor_boffset = boffset
  eb.cursor_voffset, eb.cursor_coffset = voffset_coffset(eb.text, boffset)
}

func (eb *EditBox) RuneUnderCursor() (rune, int) {
  rune_char, size := utf8.DecodeRune(eb.text[eb.cursor_boffset:])
  return rune_char, size
}

func (eb *EditBox) RuneBeforeCursor() (rune, int) {
  rune_char, size := utf8.DecodeLastRune(eb.text[:eb.cursor_boffset])
  return rune_char, size
}

func (eb *EditBox) MoveCursorOneRuneBackward() {
  if eb.cursor_boffset == 0 {
    return
  }
  _, size := eb.RuneBeforeCursor()
  eb.MoveCursorTo(eb.cursor_boffset - size)
}

func (eb *EditBox) MoveCursorOneRuneForward() {
  if eb.cursor_boffset == len(eb.text) {
    return
  }
  _, size := eb.RuneUnderCursor()
  eb.MoveCursorTo(eb.cursor_boffset + size)
}

func (eb *EditBox) DeleteRuneBackward() {
  if eb.cursor_boffset == 0 {
    return
  }
  eb.MoveCursorOneRuneBackward()
  _, size := eb.RuneUnderCursor()
  eb.text = byte_slice_remove(eb.text, eb.cursor_boffset,
    eb.cursor_boffset+size)
}

func (eb *EditBox) DeleteRuneForward() {
  if eb.cursor_boffset == len(eb.text) {
    return
  }
  _, size := eb.RuneUnderCursor()
  eb.text = byte_slice_remove(eb.text, eb.cursor_boffset,
    eb.cursor_boffset + size)
}

func (eb *EditBox) InsertRune(r rune) {
  var buf [utf8.UTFMax]byte
  n2 := utf8.EncodeRune(buf[:], r)
  eb.text = byte_slice_insert(eb.text, eb.cursor_boffset, buf[:n2])
  eb.MoveCursorOneRuneForward()
}

func (eb *EditBox) CursorX() int {
  return eb.cursor_voffset - eb.line_voffset
}

/* Rules for the text input field when it is active. */
func textEdit(ev termbox.Event) {
  if ev.Key == termbox.KeyArrowLeft {
    edit_box.MoveCursorOneRuneBackward()
  } else if ev.Key == termbox.KeyArrowRight {
    edit_box.MoveCursorOneRuneForward()
  } else if ev.Key == termbox.KeyBackspace ||
      ev.Key == termbox.KeyBackspace2 {
    edit_box.DeleteRuneBackward()
  } else if ev.Key == termbox.KeyDelete {
    edit_box.DeleteRuneForward()
  } else if ev.Key == termbox.KeySpace {
    edit_box.InsertRune(' ')
  } else if ev.Ch != 0 {
    edit_box.InsertRune(ev.Ch)
  }
}

func cli() {
  /* If config file doesn't exist, make one */
  makeConfig()
  configParse()
  err := termbox.Init()
  if err != nil {
    panic(err)
  }
  defer termbox.Close()
  termbox.SetInputMode(termbox.InputEsc & termbox.InputAlt)
  event_queue := make(chan termbox.Event)
  go func() {
    for {
      event_queue <- termbox.PollEvent()
    }
  }()
loop:
  for {
    value = ""
    /* Used for drawing menus. */
    if menu == "Welcome" {
      welcomeSettings()
    } else if menu == "New Password" {
      newPSettings()
    } else if menu == "Secure Password" {
      securePSettings()
    } else if menu == "Open Password" {
      openPSettings()
    } else if menu == "Unlock Password" {
      unlockPSettings()
    } else if menu == "Keyfile" {
      keyfileSettings()
    } else if menu == "Main Menu" {
      mainSettings()
    } else if menu == "Copy" {
      copyESettings()
    } else if menu == "Copy Content" {
      copyContentSettings()
    } else if menu == "View" {
      viewESettings()
    } else if menu == "View Content" {
      viewContentSettings()
    } else if menu == "New" {
      newESettings()
    } else if menu == "Delete" {
      deleteESettings()
    } else if menu == "Delete Content" {
      deleteContentSettings()
    } else if menu == "Edit" {
      editESettings()
    } else if menu == "Edit Content" {
      editContentSettings()
    } else if menu == "Change Passphrase" {
      cPassphraseSettings()
    } else if menu == "Import" {
      importSettings()
    } else if menu == "Export" {
      exportSettings()
    } else if menu == "Passphrase" {
      passphraseSettings()
    } else if menu == "Options" {
      optionsSettings()
    }
    draw()
    switch ev := termbox.PollEvent(); ev.Type {
    case termbox.EventKey:
      switch ev.Key {
      /* If Esc key is pressed, quit program. */
      case termbox.KeyEsc:
        break loop
      /*
       * If Ctrl-C is pressed when allowed, go back one menu and
       * reset things and possibly add contentString messages for
       * the main body of the termbox instance.
       */
      case termbox.KeyCtrlC:
        if ctrlC {
          tmpPassphrase = ""
          omit = true
          passChars = make([]bool, 0)
          newValue = make([]string, 0)
          passLen = 0
          contentString = ""
          nameGroupsList := nameGroups()
          if menu == "Copy Content" {
            contentCopied = false
            clipboard.WriteAll("")
          } else if menu == "Delete Content" {
            contentString = nameGroupsList[entryNumber - 1] +
              " Was NOT Deleted"
          } else if menu == "Export" {
            csvFile = ""
            contentString = "Content was NOT Exported!"
          } else if menu == "Passphrase" {
            contentString = "Your Passphrase/Keyfile Was NOT" +
              " Changed!"
          }
          subtractFromMenu(1)
          if menu == "Secure Password" || menu == "Passphrase" {
            if menu == "Passphrase" {
              contentString = "Your Passphrase/Keyfile Was" +
                "NOT Changed!"
            }
            subtractFromMenu(1)
          }
          bottomCaption = ""
          contentExtra = ""
          key1 = ""
          entryData = ""
          step = make([]bool, 13)
          edit_box.text = make([]byte, 0)
          edit_box.cursor_voffset = len(bottomCaption)
          edit_box.cursor_boffset = len(bottomCaption)
        }
      /*
       * If up or down keys pressed, make the values keyUpPresed or
       * keyDownPressed true for processing in the drawing phase.
       */
      case termbox.KeyArrowUp:
        keyUpPressed = true
      case termbox.KeyArrowDown:
        keyDownPressed = true
      default:
        /* Used for actions of when keys are pressed in menus. */
        if menu == "Welcome" {
          welcomeOptions(ev)
        } else if menu == "New Password" {
          newPOptions(ev)
        } else if menu == "Secure Password" {
          securePOptions(ev)
        } else if menu == "Open Password" {
          openPOptions(ev)
        } else if menu == "Unlock Password" {
          unlockPOptions(ev)
        } else if menu == "Keyfile" {
          keyfileOptions(ev)
        } else if menu == "Main Menu" {
          mainOptions(ev)
        } else if menu == "Copy" {
          copyEOptions(ev)
        } else if menu == "Copy Content" {
          copyContentOptions(ev)
        } else if menu == "View" {
          viewEOptions(ev)
        } else if menu == "View Content" {
          viewContentOptions(ev)
        } else if menu == "New" {
          newEOptions(ev)
        } else if menu == "Delete" {
          deleteEOptions(ev)
        } else if menu == "Delete Content" {
          deleteContentOptions(ev)
        } else if menu == "Edit" {
          editEOptions(ev)
        } else if menu == "Edit Content" {
          editContentOptions(ev)
        } else if menu == "Import" {
          importOptions(ev)
        } else if menu == "Export" {
          exportOptions(ev)
        } else if menu == "Change Passphrase" {
          cPassphraseOptions(ev)
        } else if menu == "Passphrase" {
          passphraseOptions(ev)
        }
      }
    }
    draw()
  }
  /*
   * If something was copied in the Copy menu and Esc is pressed, clear
   * the clipboard for security.
   */
  if contentCopied {
    clipboard.WriteAll("")
  }
}
