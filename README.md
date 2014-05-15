# LatchBox

######v0.3.1.1

**_LatchBox is created by PariahVi ([http://pariahvi.com](http://pariahvi.com)) and is licensed under a BSD License. Read LICENSE.txt for more license text._**

_A Console Based Password Management Program_

####Dependencies:

* Go
* xclip (For BSD and GNU/Linux)

####Build:

    $ go get bitbucket.org/PariahVi/latchbox

####Install:

    $ go install bitbucket.org/PariahVi/latchbox

####Platforms:

* BSD
* GNU/Linux
* OSX (need someone to test)
* Windows (needs some bug fixing, but it works)

####Protocol:

* Version 2:

    The first 2 bytes represent the version number.  The next 4 bytes represent the length of the Group Header packet.  Inside the Group Header packet, you will have group packets, each being for a different group.  Each group packet has 2 bytes for the length of the rest of that group packet, the group name, and a 2 byte group pointer.

    The rest of the bytes will be Data packets.  The first 3 bytes of each data packet say how long the rest of the data packet will be.  The next 1 byte represent the length of the NAME, then the NAME itself, then 1 byte for the USERNAME length, then the USERNAME, then 2 bytes for the PASSWORD length, then the PASSWORD, then 1 byte for the EMAIL length, then the EMAIL, then 1 byte for the URL, then the URL, then 2 bytes for the GROUP pointer, then 8 bytes for the CREATED Unix timestamp, then 8 bytes for the MODIFIED Unix timestamp, then the COMMENT (up to 65535 characters in length).

        [VERSION][GROUP_HEADER][DATA_PACKET1][DATA_PACKET2][DATA_PACKET3]

    example:

        \x00\x02\x00\x00\x00\x19\x00\x06Group1\x00\x01\x00\x0bTest/Group2\x00\x02\x00\x00\x5d\x00\x05Name1\x00\x09Username1\x00\x09Password1\x11user@example1.com\x0cexample1.com\x00\x01\x00\x00\x00\x00\x52\xC3\x5A\x80\x00\x00\x00\x00\x54\xA4\x8D\xFFCommentExample1\x00\x00\x5d\x00\x05Name2\x00\x09Username2\x00\x09Password2\x11user@example2.com\x0cexample2.com\x00\x02\x00\x00\x00\x00\x52\xC3\x5A\x80\x00\x00\x00\x00\x54\xA4\x8D\xFFCommentExample2\x00\x00\x5d\x00\x05Name3\x00\x09Username3\x00\x09Password3\x11user@example3.com\x0cexample3.com\x00\x01\x00\x00\x00\x00\x52\xC3\x5A\x80\x00\x00\x00\x00\x54\xA4\x8D\xFFCommentExample3

    This content represents the following information:

        PROTOCOL VERSION: 2
        DATA_PACKET1
            NAME: Name1
            USERNAME: Username1
            PASSWORD: Password1
            EMAIL: user@example1.com
            URL: example1.com
            GROUP: Group1
            CREATED: 2014-01-01 00:00:00
            MODIFIED: 2014-12-31 23:59:59
            COMMENT: CommentExample1
        DATA_PACKET2
            NAME: Name2
            USERNAME: Username2
            PASSWORD: Password2
            EMAIL: user@example2.com
            URL: example2.com
            GROUP: Test/Group2
            CREATED: 2014-01-01 00:00:00
            MODIFIED: 2014-12-31 23:59:59
            COMMENT: CommentExample2
        DATA_PACKET3
            NAME: Name3
            USERNAME: Username3
            PASSWORD: Password3
            EMAIL: user@example3.com
            URL: example3.com
            GROUP: Group1
            CREATED: 2014-01-01 00:00:00
            MODIFIED: 2014-12-31 23:59:59
            COMMENT: CommentExample3

* Version 1:

    The first 2 bytes represent the version number.  The next 4 bytes represent the length of the Group Header packet.  Inside the Group Header packet, you will have group packets, each being for a different group.  Each group packet has 2 bytes for the length of the rest of that group packet, the group name, and a 2 byte group pointer.

    The rest of the bytes will be Data packets.  The first 3 bytes of each data packet say how long the rest of the data packet will be.  The next 1 byte represent the length of the NAME, then the NAME itself, then 1 byte for the USERNAME length, then the USERNAME, then 2 bytes for the PASSWORD length, then the PASSWORD, then 1 byte for the EMAIL length, then the EMAIL, then 1 byte for the URL, then the URL, then 2 bytes for the GROUP pointer, then 1 byte for the TYPE, then 4 bytes for the CREATED Unix timestamp, then 4 bytes for the MODIFIED Unix timestamp, then the COMMENT (up to 65535 characters in length).

        [VERSION][GROUP_HEADER][DATA_PACKET1][DATA_PACKET2][DATA_PACKET3]

    example:

        \x00\x01\x00\x00\x00\x19\x00\x06Group1\x00\x01\x00\x0bTest/Group2\x00\x02\x00\x00\x56\x00\x05Name1\x00\x09Username1\x00\x09Password1\x11user@example1.com\x0cexample1.com\x00\x01\x00\x52\xC3\x5A\x80\x54\xA4\x8D\xFFCommentExample1\x00\x00\x56\x00\x05Name2\x00\x09Username2\x00\x09Password2\x11user@example2.com\x0cexample2.com\x00\x02\x00\x52\xC3\x5A\x80\x54\xA4\x8D\xFFCommentExample2\x00\x00\x56\x00\x05Name3\x00\x09Username3\x00\x09Password3\x11user@example3.com\x0cexample3.com\x00\x01\x00\x52\xC3\x5A\x80\x54\xA4\x8D\xFFCommentExample3

    This content represents the following information:

        PROTOCOL VERSION: 1
        DATA_PACKET1
            NAME: Name1
            USERNAME: Username1
            PASSWORD: Password1
            EMAIL: user@example1.com
            URL: example1.com
            GROUP: Group1
            TYPE: 0
            CREATED: 2014-01-01 00:00:00
            MODIFIED: 2014-12-31 23:59:59
            COMMENT: CommentExample1
        DATA_PACKET2
            NAME: Name2
            USERNAME: Username2
            PASSWORD: Password2
            EMAIL: user@example2.com
            URL: example2.com
            GROUP: Test/Group2
            TYPE: 0
            CREATED: 2014-01-01 00:00:00
            MODIFIED: 2014-12-31 23:59:59
            COMMENT: CommentExample2
        DATA_PACKET3
            NAME: Name3
            USERNAME: Username3
            PASSWORD: Password3
            EMAIL: user@example3.com
            URL: example3.com
            GROUP: Group1
            TYPE: 0
            CREATED: 2014-01-01 00:00:00
            MODIFIED: 2014-12-31 23:59:59
            COMMENT: CommentExample3

####Config File:

After starting LatchBox, a config file and latchbox folder will be created.  In Windows, that folder will be at `%USERPROFILE%\AppData\Local\latchbox\`, otherwise it the folder will be at `$HOME/.latchbox/`.  The folder will contain a file called `config.txt`.  You can edit the config file by changing the contents inside of the quotes.

To make a backup file of your password files in the backup folder inside of the latchbox folder when your password file updates for the first time after opening the password file, make sure makeBackups is set to "true" (case-insensitive).

To set the default password file location, edit defaultPasswordFile.  The default password file must be empty or not exist in order to use it as the default NEW password file, otherwise if it follows what is expected of an encrypted password file, it will be the default OPEN password file.

####Security:

LatchBox uses AES256 encryption to encrypt the password file.  It also uses bcrypt with a cost value of 12 followed by SHA256 to create the 256-bit key from your passphrase to encrypt the data.  If you include a keyfile for your passphrase, the SHA512 hash of the keyfile will be appended to the passphrase before the full passphrase is hashed  The keyfile is a file that can be used to encrypt a password file and can be any file of any content size.  The first 29 bytes of the saved password file are the salt to hash the passphrase.  The next 16 bytes of the saved password file are the AES initialization vector, which acts much like a salt to make the encryption much harder to predict.  The final 64 bytes are a SHA512 hash of the unencrypted contents of the file to use as a checksum to see if your passphrase was correct to decrypt the password file.  Anything between the AES initialization vector and the final 64 bytes is the encrypted password file content, which will be a multiple of 16 bytes and at least 16 bytes long due to padding during the encryption process.

Every time the password file is overwritten by LatchBox, a new salt is generated and hashed with the passphrase to create a new encryption key.  The password file is overwritten after editing an entry, making a new entry or changing the password file passphrase.  Creating a new password file using NEW at the beginning will automatically create an encrypted password file.
