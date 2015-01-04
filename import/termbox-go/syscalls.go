// +build ignore

/*-
 * Copyright (C) 2015 Vi Grey.  All rights reserved
 * Copyright (C) 2012 Georg Reinke <guelfey@googlemail.com>
 * Copyright (C) 2012 nsf <no.smile.face@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package termbox

/*
#include <termios.h>
#include <sys/ioctl.h>
*/
import "C"

type syscall_Termios C.struct_termios

const (
  syscall_IGNBRK = C.IGNBRK
  syscall_BRKINT = C.BRKINT
  syscall_PARMRK = C.PARMRK
  syscall_ISTRIP = C.ISTRIP
  syscall_INLCR  = C.INLCR
  syscall_IGNCR  = C.IGNCR
  syscall_ICRNL  = C.ICRNL
  syscall_IXON   = C.IXON
  syscall_OPOST  = C.OPOST
  syscall_ECHO   = C.ECHO
  syscall_ECHONL = C.ECHONL
  syscall_ICANON = C.ICANON
  syscall_ISIG   = C.ISIG
  syscall_IEXTEN = C.IEXTEN
  syscall_CSIZE  = C.CSIZE
  syscall_PARENB = C.PARENB
  syscall_CS8    = C.CS8
  syscall_VMIN   = C.VMIN
  syscall_VTIME  = C.VTIME
  /*
   * on darwin change these to (on *bsd too?):
   * C.TIOCGETA
   * C.TIOCSETA
   */
  syscall_TCGETS = C.TCGETS
  syscall_TCSETS = C.TCSETS
)
