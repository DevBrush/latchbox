// Copyright 2014 PariahVi (http://pariahvi.com).
// LatchBox is licensed under a BSD License.
// Read LICENSE.txt for more license text.

// A Console Based Password Management Program
package main

import (
    "github.com/PariahVi/clipboard"
    "github.com/jameskeane/bcrypt"
    "github.com/nsf/termbox-go"
    "github.com/pmylund/sortutil"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "crypto/sha512"
    "errors"
    "io/ioutil"
    "math"
    "math/big"
    "os"
    "os/user"
    "runtime"
    "strconv"
    "strings"
    "time"
    "unicode/utf8"
)

const (
    // Protocol Version to save password file under.
    protocolVersion = 2
    version = "v0.3.1.6"
    title = "Latchbox " + version + " (Esc:QUIT"
    // uppercase, lowercase, digits and punctuation are used to generate
    // random passwords.
    uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lowercase = "abcdefghijklmnopqrstuvwxyz"
    digits = "1234567890"
    punctuation = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
    // YYYY-MM-DD hh:mm:ss 24-hour time (computer's localtime)
    timeLayout = "2006-01-02 15:04:05"
    // YYYYMMDDhhmmss 24-hour time (computer's localtime)
    backupLayout = "20060102150405"
)

var (
    contentCopied bool
    passChars []bool
    newValue []string
    passLen int
    backupSaved bool
    backupContents []byte
    entryData string
    fPath string
    pFileVersion uint16
    value string
    checksum bool
    backup bool
    defaultFile string
    errMsg string
    passphrase string
    tmpPassphrase string
    key string
    location string
    fileContents []byte
    names []string
    usernames []string
    passwords []string
    emails []string
    urls []string
    groups []string
    comments []string
    created []string
    modified []string
    groupDict = make(map[string]string)
    orderDict = make(map[string]string)
    locationTitle string
    options string
    ctrlC bool
    menu = "Welcome"
    ctrlCValue string
    topTitle string
    menuList = []string{menu}
    w, h int
    passwordInput bool
    step = make([]bool, 13)
    key1 string
    bottomCaption string
    contentString string
    contentExtra string
    keyUpPressed bool
    keyDownPressed bool
    top int
    orderList []int
    edit_box EditBox
    tmpDefault string
    entryNumber int
    show bool
    configDir string
    omit bool
)

// Parses the decrypted password file and sorts the information in
// accordance to the protocol for use with the program.
func parseFile() {
    var err bool
    var pointer int
    var packetPointer int
    var hGroupPointer string
    if len(fileContents) >= 2 {
        pFileVersion = uint16(getLen(fileContents[pointer: pointer + 2]))
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
        if pFileVersion == 1 {
            packetPointer += 1
        }
        getTime(packet, &created, &packetPointer, pFileVersion, &err)
        getTime(packet, &modified, &packetPointer, pFileVersion, &err)
        var comment string
        if len(packet) - packetPointer >= 0 && !err {
            comment = string(packet[packetPointer:])
            comments = append(comments, comment)
        } else {
            err = true
        }
    }
    if err {
        lock()
        contentString = "Corrupted Password File"
    }
}

// Returns the length of the next packet section along with the content of
// the packet section.
func parseInfo(packet []byte, byteLen int, pointer *int, err *bool) (
        packetLen int, content []byte) {
    var pLen int
    var pContent []byte
    if len(packet) - *pointer >= byteLen && !*err {
        pLen = getLen(packet[*pointer: *pointer + byteLen])
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

// Get YYYY-MM-DD hh:mm:ss timestamp out of 8 bytes (protocol version > 1)
// or 4 bytes (protocol version 1).
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
        for x := 0; x < len(timeByteString); x++ {
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

// Organize data into password file protocol, then encrypt the
// password file and write to file.  If first time writing and backups
// allowed, make a backup.
func writeData() {
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
    if len(names) > 0 {
        doBackup()
    }
    ioutil.WriteFile(fPath, dataEncrypt, 0644)
}

// Convert YYYY-MM-DD hh:mm:ss timestamp to local Unix time.
func timeToUnix(value string) int64 {
    local, _ := time.LoadLocation("Local")
    toTime, _ := time.ParseInLocation(timeLayout, value, local)
    return toTime.Unix()
}

// Make map of [groupName]groupPointer (group pointer can be up to 65535).
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

// Returns byte slice of protocol for groups and group pointers.
func groupHeader() []byte {
    var groupData []byte
    for x := range groupDict {
        groupData = append(groupData, strLenAppend([]byte(x), 2)...)
        groupData = append(groupData, []byte(groupDict[x])...)
    }
    groupData = strLenAppend(groupData, 4)
    return groupData
}

// Returns byteNum bytes that signify the length of s and appends s
// to the bytes.
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

// Converts i to to a byte slice of byteNum length.
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

// Checks if the string char is in the string input.
func inString(input, char string) bool {
    for i := 0; i < len(input); i++ {
        if input[i] == char[0] {
            if len(char) == 2 {
                if i < len(input) - 1 {
                    if input[i + 1] == char[1] {
                        return true
                    }
                }
            } else {
                return true
            }
        }
    }
    return false
}

// Converts byteString to an int
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

// Returns a case insensitive sorted string slice of the groups
// concatenated with the names.
func nameGroups() []string {
    var nameGroupsList []string
    for i := 0; i < len(names); i++ {
        if groups[i] == "" {
            nameGroupsList = append(nameGroupsList, names[i])
        } else {
            nameGroupsList = append(nameGroupsList, groups[i] + "/" + names[i])
        }
    }
    nameGroupsList = ciSort(nameGroupsList)
    return nameGroupsList
}

// Case insentitive sorts the string slice list.
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

// Resets variables and brings the user back to the Welcome menu to either
// make a NEW password file or OPEN an old one.
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

// Uses bcrypt with a cost value of 12 and salt to hash passValue, then
// uses SHA256 to hash the value that was hashed with bcrypt to create a
// 32-bit byte slice to encrypt the password file using AES256.
func hashKey(passValue, salt string) []byte {
    hashed, _ := bcrypt.Hash(passValue, salt)
    hash := sha256.New()
    hash.Write([]byte(hashed))
    return hash.Sum(nil)
}

// Pads the byte slice message and encrypts it using the byte string key and AES256 CBC.
func encrypt(message, key []byte) []byte {
    x := (aes.BlockSize - len(message) % aes.BlockSize)
    if x == 0 {
        x = 16
    }
    paddedMessage := message
    for i := 0; i < x; i++ {
        paddedMessage = append(paddedMessage, uint8(x))
    }
    block, err := aes.NewCipher(key)
    if err != nil {
        panic(err)
    }
    ciphertext := make([]byte, len(paddedMessage))
    iv := make([]byte, aes.BlockSize)
    if _, err := rand.Read(iv); err != nil {
        panic(err)
    }
    mode := cipher.NewCBCEncrypter(block, iv)
    mode.CryptBlocks(ciphertext, paddedMessage)
    ciphertext = append(iv, ciphertext...)
    return ciphertext
}

// Decrypts the byte slice ciphertext and unpads it.
func decrypt(ciphertext, key []byte) []byte {
    block, err := aes.NewCipher(key)
    if err != nil {
        panic(err)
    }
    plaintext := make([]byte, len(ciphertext[aes.BlockSize:]))
    iv := ciphertext[:aes.BlockSize]
    mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(plaintext, ciphertext[aes.BlockSize:])
    padding := 0
    if len(plaintext) > 0 {
        padding = int(plaintext[len(plaintext) - 1])
    }
    if padding > 16 {
        padding = 0
    }
    plaintext = plaintext[:len(plaintext) - padding]
    return plaintext
}

// Checks to see if the encrypted password file (fc) looks legitimate for
// length and the salt, then parses out the salt, ciphertext (ct), and
// the sha512 hash of the decrypted ciphertext, which is used to test
// if the decryption key was correct while decrypting the encrypted
// password file.  If anything isn't as expected, an error is returned.
func parseCt(fc []byte) (salt []byte, ct []byte, hash []byte, err error) {
    if len(fc) < 125 {
        return nil, nil, nil, errors.New("Ciphertext length too small")
    } else if string(fc[:4]) != "$2a$" || (fc[5] != '$' && fc[6] != '$') {
        return nil, nil, nil, errors.New("Incorrect Salt Value")
    } else if (len(fc) - 109) % 16 != 0 {
        return nil, nil, nil, errors.New("Ciphertext not divisible by 16")
    }
    return fc[:29], fc[29:len(fc) - 64], fc[len(fc) - 64:], nil
}

// Draws the termbox instance along with the content and allows for
// resizing and shows if Ctrl-C can be used or if scrolling is allowed
// using the up and down key.
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

// Returns a string slice with each value being a single line to draw.
// Uses w to figure out how to split up valueString.
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

// Parses the config file to figure out the default password file location
// and if backups are allowed.
func configParse() {
    configFile := configDir + "config.txt"
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
    }
}

// WELCOME TO LATCHBOX menu
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
            menu = "New Password"
            menuList = append(menuList, menu)
        } else if ev.Ch == 'o' {
            menu = "Open Password"
            menuList = append(menuList, menu)
        }
    }
}

// NEW PASSWORD FILE
func newPSettings() {
    ctrlC = true
    passwordInput = false
    locationTitle = "NEW PASSWORD FILE"
    options = "Enter:CONFIRM"
    bottomCaption = "Path for New Password File: "
    termbox.SetCursor(len(bottomCaption) + edit_box.CursorX(), h - 1)
    tmpDefault = defaultFile
    if defaultFile != "" {
        if len(defaultFile) > 1 {
            if defaultFile[:2] == "~/" {
                usr, _ := user.Current()
                defaultFile = usr.HomeDir + defaultFile[1:]
            }
        }
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
                menu = "Secure Password"
                menuList = append(menuList, menu)
            }
        } else {
            contentExtra = "File Name Required"
        }
    }
}

// SECURE NEW PASSWORD FILE
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
    options += " KEY FILE"
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
                    menu = "Keyfile"
                    menuList = append(menuList, menu)
                } else {
                    passphrase = value
                    writeData()
                    contentString = "Your Password File Was Created" +
                        "Successfully!"
                    menu = "Main Menu"
                    menuList = append(menuList, menu)
                }
            } else {
                contentString = "New Passphrases Do Not Match"
                step[0] = true
            }
            key1 = ""
        }
    }
}

// OPEN PASSWORD FILE
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
        if len(defaultFile) > 1 {
            if defaultFile[:2] == "~/" {
                usr, _ := user.Current()
                defaultFile = usr.HomeDir + defaultFile[1:]
            }
        }
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
        if len(value) > 1 {
            if value[:2] == "~/" {
                usr, _ := user.Current()
                value = usr.HomeDir + value[1:]
            }
        }
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
                menu = "Unlock Password"
                menuList = append(menuList, menu)
            }
        }
    }
}

// UNLOCK PASSWORD FILE
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
    options += " KEY FILE"
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
            menu = "Keyfile"
            menuList = append(menuList, menu)
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
                parseFile()
                contentString = ""
                menu = "Main Menu"
                menuList = append(menuList, menu)
            } else {
                contentString = "Incorrect Passphrase/Keyfile Combination"
            }
        }
    }
}

// If INCLUDE KEYFILE was selected.
func keyfileSettings() {
    ctrlC = true
    passwordInput = false
    bottomCaption = "Path to Keyfile: "
    options = "Enter:CONFIRM"
    termbox.SetCursor(len(bottomCaption) + edit_box.CursorX(), h - 1)
}

// Allows keyfile to be included.  If included, the file's contents will
// be hashed with SHA512 and appended to the passphrase before hashing
// the key (passphrase) for encryption/decryption of the password file.
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
                writeData()
                contentString = "Your Password File Was Created Successfully!"
                tmpPassphrase = ""
                menu = "Main Menu"
                menuList = append(menuList, menu)
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
                    parseFile()
                    contentString = ""
                    tmpPassphrase = ""
                    menu = "Main Menu"
                    menuList = append(menuList, menu)
                } else {
                    contentString = "Incorrect Passphrase/Keyfile " +
                        "Combination"
                    tmpPassphrase = ""
                    omit = true
                    menuList = menuList[:len(menuList) - 1]
                    menu = menuList[len(menuList) - 1]
                }
            } else {
                if step[0] {
                    if passphrase == tmpPassphrase {
                        contentString = ""
                        step[0], step[1] = false, true
                        tmpPassphrase = ""
                        omit = true
                        menuList = menuList[:len(menuList) - 1]
                        menu = menuList[len(menuList) - 1]
                    } else {
                        contentString = "Incorrect Passphrase/Keyfile " +
                            "Combination"
                        tmpPassphrase = ""
                        omit = true
                        menuList = menuList[:len(menuList) - 1]
                        menu = menuList[len(menuList) - 1]
                    }
                } else {
                    passphrase = tmpPassphrase
                    writeData()
                    contentString = "Your Passphrase/Keyfile Was " +
                        "Successfully Changed!"
                    tmpPassphrase = ""
                    menu = "Main Menu"
                    menuList = append(menuList, menu)
                }
            }
        }
    }
}

// Get Content of filePath for the keyFile to help decrypt the password
// file.
func addKeyFile(filePath string) ([]byte, error) {
    if len(filePath) > 1 {
        if filePath[:2] == "~/" {
            usr, _ := user.Current()
            filePath = usr.HomeDir + filePath[1:]
        }
    }
    content, err := ioutil.ReadFile(filePath)
    if err != nil {
        return nil, err
    }
    return content, nil
}

// MAIN MENU
func mainSettings() {
    ctrlC = false
    termbox.HideCursor()
    bottomCaption = ""
    locationTitle = "MAIN MENU"
    if len(names) > 0 {
        options = "c:COPY  v:VIEW  n:NEW  d:DELETE  e:EDIT  p:PASSPHRASE  " +
            "l:LOCK"
    } else {
        options = "n:NEW  p:PASSPHRASE  l:LOCK"
    }
}

func mainOptions(ev termbox.Event) {
    if ev.Ch != 0 {
        if len(names) > 0 {
            if ev.Ch == 'c' {
                menu = "Copy"
                menuList = append(menuList, menu)
            } else if ev.Ch == 'v' {
                menu = "View"
                menuList = append(menuList, menu)
            } else if ev.Ch == 'd' {
                menu = "Delete"
                menuList = append(menuList, menu)
            } else if ev.Ch == 'e' {
                step[0] = true
                menu = "Edit"
                menuList = append(menuList, menu)
            }
        }
        if ev.Ch == 'n' {
            step[0] = true
            menu = "New"
            menuList = append(menuList, menu)
        } else if ev.Ch == 'p' {
            contentString = ""
            menu = "Change Passphrase"
            menuList = append(menuList, menu)
        } else if ev.Ch == 'l' {
            lock()
        }
    }
}

// COPY ENTRY (first menu)
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
                menu = "Copy Content"
                menuList = append(menuList, menu)
            }
        }
    }
}

// COPY ENTRY (second menu)
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
                menuList = menuList[:len(menuList) - 2]
                menu = menuList[len(menuList) - 1]
                contentString = "Unable to Copy Content to Clipboard"
            }
        }
    }
}

// VIEW ENTRY (first menu)
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
                menu = "View Content"
                menuList = append(menuList, menu)
            }
        }
    }
}

// VIEW ENTRY (second menu)
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
        for x := 0; x < len(passwords[orderList[entryNumber - 1]]); x++ {
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

// NEW ENTRY
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
                    if !inString(value, "/") {
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
                if len(value) < 66536 {
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
                                    !inString(value, "/ ") {
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
                if len(value) < 66536 {
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
                    writeData()
                    menuList = menuList[:len(menuList) - 1]
                    menu = menuList[len(menuList) - 1]
                    contentString = ""
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

// DELETE ENTRY (first menu)
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
                menu = "Delete Content"
                menuList = append(menuList, menu)
            }
        }
    }
}

// DELETE ENTRY (second menu)
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
            contentString = nameGroupsList[entryNumber - 1] +
                " Was Successfully Deleted"
            menuList = menuList[:len(menuList) - 1]
            menu = menuList[len(menuList) - 1]
            writeData()
        } else if ev.Ch == 'n' {
            contentString = nameGroupsList[entryNumber - 1] +
                " Was NOT Deleted"
            menuList = menuList[:len(menuList) - 1]
            menu = menuList[len(menuList) - 1]
        }
    }
}

// EDIT ENTRY (first menu)
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
                menu = "Edit Content"
                menuList = append(menuList, menu)
            }
        }
    }
}

// EDIT ENTRY (second menu)
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
                    menuList = menuList[:len(menuList) - 1]
                    menu = menuList[len(menuList) - 1]
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
                    menuList = menuList[:len(menuList) - 1]
                    menu = menuList[len(menuList) - 1]
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
                    if len(value) < 66536 {
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
                        menuList = menuList[:len(menuList) - 1]
                        menu = menuList[len(menuList) - 1]
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
                        !inString(value, "/") {
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
                        menuList = menuList[:len(menuList) - 1]
                        menu = menuList[len(menuList) - 1]
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
                    menuList = menuList[:len(menuList) - 1]
                    menu = menuList[len(menuList) - 1]
                } else {
                    contentExtra = "Username Too Long"
                }
            } else if entryData == "Email" {
                if len(value) < 256 {
                    contentString = "Email Changed"
                    emails[num] = value
                    menuList = menuList[:len(menuList) - 1]
                    menu = menuList[len(menuList) - 1]
                }
            } else if entryData == "URL" {
                if len(value) < 256 {
                    contentString = "URL Changed"
                    urls[num] = value
                    menuList = menuList[:len(menuList) - 1]
                    menu = menuList[len(menuList) - 1]
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
                            !inString(group, "//") && !inString(group, "/ ") {
                        if !duplicateNameGroups(nameGroupsList) {
                            contentString = "Group Name Changed"
                            groups[num] = value
                            menuList = menuList[:len(menuList) - 1]
                            menu = menuList[len(menuList) - 1]
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
                if len(value) < 66536 {
                    contentString = "Comment Changed"
                    comments[num] = value
                    menuList = menuList[:len(menuList) - 1]
                    menu = menuList[len(menuList) - 1]
                }
            }
        }
    }
    if menu == "Main Menu" {
        contentExtra = ""
        entryData = ""
        modified[num] = time.Now().Format(timeLayout)
        writeData()
    }
}

// CHANGE PASSPHRASE/KEYFILE (first menu)
func cPassphraseSettings() {
    ctrlC = true
    termbox.HideCursor()
    locationTitle = "CHANGE PASSPHRASE/KEYFILE"
    options = "y:YES n:NO"
}

func cPassphraseOptions(ev termbox.Event) {
    if ev.Ch == 'y' {
        omit = true
        step[0] = true
        menu = "Passphrase"
        menuList = append(menuList, menu)
    } else if ev.Ch == 'n' {
        menu = "Main Menu"
        menuList = menuList[:len(menuList) - 1]
    }
}

// CHANGE PASSPHRASE/KEYFILE (second menu)
func passphraseSettings() {
    if menuList[len(menuList) - 2] == "Change Passphrase" {
        menuList = append(menuList[:len(menuList) - 2],
            menuList[len(menuList) - 1])
    }
    ctrlC = true
    passwordInput = true
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
    options += " KEY FILE"
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
                menu = "Keyfile"
                menuList = append(menuList, menu)
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
                    menu = "Keyfile"
                    menuList = append(menuList, menu)
                } else {
                    passphrase = value
                    writeData()
                    contentString = "Your Passphrase/Keyfile Was " +
                        "Successfully Changed!"
                    menu = "Main Menu"
                    menuList = append(menuList, menu)
                }
            } else {
                contentString = "New Passphrases Do Not Match"
                step[1] = true
            }
            key1 = ""
        }
    }
}

// Creates a string with the group name combinations along with a number
// in square brackets ahead of it to indicate that group name combination
// option for selecting the group name entry to use.
func displayNameGroups() string {
    content := ""
    nameGroupsList := nameGroups()
    for x := 0; x < len(nameGroupsList); x++ {
        content += "[" + strconv.Itoa(x + 1) + "] " + nameGroupsList[x] + "\n"
    }
    return content[:len(content) - 1]
}

// generate a random password with criteria ([uppercase, lowercase, digits
// punctuation] (ulds), and lenth (pLen)).  Needs at least 4 for the
// generated password length.  If NO was used for all criteria in ulds, a
// password will be generated with only lowercase characters.  The password
// is guaranteed to have at least one of every type of character allowed
// under ulds.
func genPass (pLen uint16, ulds []bool) string {
    var password []byte
    var passwordString string
    if ulds[0] {
        passwordString += uppercase
    }
    if ulds[1] {
        passwordString += lowercase
    }
    if ulds[2] {
        passwordString += digits
    }
    if ulds[3] {
        passwordString += punctuation
    }
    if passwordString == "" {
        passwordString += lowercase
    }
    for x := 0; uint16(x) < pLen; x++ {
        letter := getRandNumber(int64(len(passwordString)))
        password = append(password, passwordString[letter])
    }
    var randomValues []uint16
    for x := 0; x < 4; x++ {
        position := getRandNumber(int64(pLen))
        var bad bool
        for y := 0; y < len(randomValues); y++ {
            if randomValues[y] == uint16(position) {
                bad = true
            }
        }
        if bad {
            x--
        } else {
            randomValues = append(randomValues, uint16(position))
        }
    }
    characters := []string{uppercase, lowercase, digits, punctuation}
    for x := 0; x < 4; x++ {
        if ulds[x] {
            z := getRandNumber(int64(len(characters[x])))
            password[randomValues[x]] = characters[x][z]
        }
    }
    return string(password)
}

// Get a random int between 0 and number.
func getRandNumber(number int64) int {
    randNumber, _ := rand.Int(rand.Reader, big.NewInt(number))
    randString := randNumber.String()
    randInt, _ := strconv.Atoi(randString)
    return randInt
}
// Return true if there are duplicate values in nameGroupList.
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
        _, size := utf8.DecodeRune(text)
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
    text           []byte
    line_voffset   int
    cursor_boffset int
    cursor_voffset int
    cursor_coffset int
}

func (eb *EditBox) Layout(x, y, w, h int) {
    eb.AdjustVOffset(w)
    const coldef = termbox.ColorDefault
    fill(x, y, w, h, termbox.Cell{Ch: ' '})
    t := eb.text
    // Input * characters if passwordInput is true
    if passwordInput {
        t = make([]byte, 0)
        for i := 0; i < len(eb.text); i++ {
            t = append(t, '*')
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
    return utf8.DecodeRune(eb.text[eb.cursor_boffset:])
}

func (eb *EditBox) RuneBeforeCursor() (rune, int) {
    return utf8.DecodeLastRune(eb.text[:eb.cursor_boffset])
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

// Rules for the text input field when it is active.
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

// Makes latchbox directory if one doesn't exist and creates config
// if it doesn't exist.  If config.txt exists, but not config, config.txt
// will be renamed to config.
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

// Makes backup files (and a backup directory inside of the latchbox
// directory if it doesn't exist) and makes a copy of the password file
// as it was when it was opened on the first time it is saved after
// opening it.
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

func main() {
    // Check if BSD, GNU/Linux or Mac OSX.
    if runtime.GOOS == "windows" || runtime.GOOS == "plan9" {
        panic("Unsupported Operating System")
    }
    // If config file doesn't exist, make one
    makeConfig()
    configParse()
    err := termbox.Init()
    if err != nil {
        panic(err)
    }
    defer termbox.Close()
    event_queue := make(chan termbox.Event)
    go func() {
        for {
            event_queue <- termbox.PollEvent()
        }
    }()
loop:
    for {
        value = ""
        // Used for drawing menus.
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
        } else if menu == "Passphrase" {
            passphraseSettings()
        }
        draw()
        switch ev := termbox.PollEvent(); ev.Type {
        case termbox.EventKey:
            switch ev.Key {
            // If Esc key is pressed, quit program.
            case termbox.KeyEsc:
                break loop
            // If Ctrl-C is pressed when allowed, go back one menu and
            // reset things and possibly add contentString messages for
            // the main body of the termbox instance.
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
                    }
                    if menu == "Passphrase" {
                        contentString = "Your Passphrase/Keyfile Was NOT" +
                            " Changed!"
                    }
                    menuList = menuList[:len(menuList) - 1]
                    menu = menuList[len(menuList) - 1]
                    if menu == "Secure Password" || menu == "Passphrase" {
                        if menu == "Passphrase" {
                            contentString = "Your Passphrase/Keyfile Was" +
                                "NOT Changed!"
                        }
                        menuList = menuList[:len(menuList) - 1]
                        menu = menuList[len(menuList) - 1]
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
            // If up or down keys pressed, make the values keyUpPresed or
            // keyDownPressed true for processing in the drawing phase.
            case termbox.KeyArrowUp:
                keyUpPressed = true
            case termbox.KeyArrowDown:
                keyDownPressed = true
            default:
                // Used for actions of when keys are pressed in menus.
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
                } else if menu == "Change Passphrase" {
                    cPassphraseOptions(ev)
                } else if menu == "Passphrase" {
                    passphraseOptions(ev)
                }
            }
        }
        draw()
    }
    // If something was copied in the Copy menu and Esc is pressed, clear
    // the clipboard for security.
    if contentCopied {
        clipboard.WriteAll("")
    }
}
