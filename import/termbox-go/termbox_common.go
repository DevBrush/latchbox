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

/* private API, common OS agnostic part */

const cursor_hidden = -1

type cellbuf struct {
  width  int
  height int
  cells  []Cell
}

func (this *cellbuf) init(width, height int) {
  this.width = width
  this.height = height
  this.cells = make([]Cell, width*height)
}

func (this *cellbuf) resize(width, height int) {
  if this.width == width && this.height == height {
    return
  }
  oldw := this.width
  oldh := this.height
  oldcells := this.cells
  this.init(width, height)
  this.clear()
  minw, minh := oldw, oldh
  if width < minw {
    minw = width
  }
  if height < minh {
    minh = height
  }
  for i := 0; i < minh; i++ {
    srco, dsto := i*oldw, i*width
    src := oldcells[srco : srco+minw]
    dst := this.cells[dsto : dsto+minw]
    copy(dst, src)
  }
}

func (this *cellbuf) clear() {
  for i := range this.cells {
    c := &this.cells[i]
    c.Ch = ' '
    c.Fg = foreground
    c.Bg = background
  }
}

func is_cursor_hidden(x, y int) bool {
  return x == cursor_hidden || y == cursor_hidden
}

/*
 * somewhat close to what wcwidth does, except rune_width doesn't return 0 or
 * -1, it's always 1 or 2
 */
func rune_width(r rune) int {
  if r >= 0x1100 &&
    (r <= 0x115f || r == 0x2329 || r == 0x232a ||
      (r >= 0x2e80 && r <= 0xa4cf && r != 0x303f) ||
      (r >= 0xac00 && r <= 0xd7a3) ||
      (r >= 0xf900 && r <= 0xfaff) ||
      (r >= 0xfe30 && r <= 0xfe6f) ||
      (r >= 0xff00 && r <= 0xff60) ||
      (r >= 0xffe0 && r <= 0xffe6) ||
      (r >= 0x20000 && r <= 0x2fffd) ||
      (r >= 0x30000 && r <= 0x3fffd)) {
    return 2
  }
  return 1
}
