# LatchBox

_A Console Based Password Management Program_

**_LatchBox is created by Vi Grey (https://vigrey.com) <vi@vigrey.com> and is licensed under the BSD 2-Clause License.  Read LICENSE for more license text._**

#### Description:
LatchBox is a CLI based password manager that saves account information in an encrypted file that can securely be accessed and stored by the user.  The encrypted password file is locked using a master passphrase and/or a keyfile.

#### Platforms:
- BSD
- GNU/Linux
- OS X

#### Build Dependencies:
- gb
- Go >= 1.1.1

#### Optional Dependencies:
- xclip (For BSD and GNU/Linux)
- shred (For GNU/Linux)
- gshred (For BSD)

#### Install:
    $ make
    $ sudo make install

#### Uninstall:
    $ sudo make uninstall

#### Usage:
    $ latchbox -h
    Usage: latchbox [ OPTIONS ]...

    Options:
      -h, --help       Print Help (this message) and exit
          --version    Print version information and exit

#### Import:
You can import .csv files made from LastPass or KeePass to your password file in LatchBox.

Expected csv labels (case insensitive) for the different entries are:

- *name* or *account* for **NAME**
- *username* or *login name* for **USERNAME**
- *password* for **PASSWORD**
- *url* or *web site* for **URL**
- *grouping* or *group* for **GROUP**
- *extra* or *comments* for **COMMENT**

These labels can be in any order and some can be excluded as long as *name* or *account* is included.  Quotation marks are allowed every csv field as well.

To convert from other formats (Mostly LastPass and KeePass) and prevent conflicts, the **NAME** entries will replace **/** symbols with **\** symbols and the **GROUP** entries will swap both **/** symbols and **\** symbols.

#### Export:
Before you export a csv file of your password data, you will need to input your passphrase/keyfile combination.  After that, a csv file will be made in the chosen path with the csv labels in the order of:

name,username,password,url,grouping,extra

where grouping is the group and extra is the comment.  This is the exact same layout LastPass uses, so if you want to export to KeePass, it is recommended that you import as a LastPass .csv file.

Just like importing, **NAME** entries will replace **/** symbols with **\** symbols and **GROUP** entries will swap both the **/** symbols and the **\** symbols.  This is to make sure groups are separated by **\** symbols like hello\world, which LastPass and KeePass understand, rather than hello/world, which is LatchBox syntax.

#### Config File:
After starting LatchBox, a config file and latchbox folder will be created.  That folder will be at `$HOME/.latchbox/`.  The folder will contain a file called `config`.  You can edit the config file by changing the contents inside of the quotes.

To make a backup file of your password files in the backup folder inside of the latchbox folder when your password file updates for the first time after opening the password file, make sure **makeBackups** is set to "true" (case-insensitive).

To set the default password file location, edit **defaultPasswordFile**.  The default password file must be empty or not exist in order to use it as the default NEW password file, otherwise if it follows what is expected of an encrypted password file, it will be the default OPEN password file.

To set the encryption cipher, edit **cipher**, which is "Chacha20Poly1305" (case-insensitive) by default but can be set to "AES256-GCM" (case-insensitive).

To set the number of HMAC-SHA256 based PBKDF2 iterations for making the encryption key, set **iterations**.  The number of iterations must be at least "100000" and is normally managed by the program itself.  The default number of iterations if not set is 100000 or however many iterations are required to take up 0.5 seconds, whichever is the higher amount.

#### Security:
LatchBox uses Chacha20Poly1305 or AES256-GCM to encrypt the password file [see LatchBox File Specifications].  The encryption key is created by using a HMAC-SHA256 based PBKDF2 hash of the LatchBox file passphrase.  If a key file is included, an HMAC-SHA512 hash using the file content as the secret key and the passphrase as the message will be created before doing an HMAC-SHA256 based PBKDF2 hash on that value to create the encryption key.

#### LatchBox File Specification:
LatchBox File protocol specifications can be found in `docs/latchbox-spec.txt`.
