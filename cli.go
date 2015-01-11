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
 * Draws the termbox instance along with the content and allows for
 * resizing and shows if Ctrl-C can be used or if scrolling is allowed
 * using the up and down key.
 */
package main

import (
  "github.com/PariahVi/latchbox/import/clipboard"
  "github.com/PariahVi/latchbox/import/termbox-go"
  "fmt"
  "strings"
  "unicode/utf8"
  "os"
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

func cli() {
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
      fmt.Printf("latchbox: invalid option -- '%s'\nTry 'latchbox" +
                 "--help' for more information.\n", string(os.Args[i]))
      os.Exit(1)
    }
  }
  if helpFlag || versionFlag {
    if helpFlag {
      fmt.Printf("Usage: latchbox [ OPTIONS ]...\n\nOptions:\n" +
                 "  -h, --help       Print Help (this message) and exit\n" +
                 "      --version    Print version information and exit\n")
    } else {
      fmt.Printf("LatchBox %s\n", versionNum)
    }
  } else {
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
}
