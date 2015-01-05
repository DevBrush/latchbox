/*-
 * Copyright (c) 2015 Vi Grey. All rights reserved.
 * Copyright (c) 2012 Patrick Mylund Nielsen
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

package sortutil

import (
  "reflect"
  "sort"
  "strings"
  "time"
)

/*
 * Ordering decides the order in which the specified data is
 * sorted.
 */
type Ordering int

/*
 * A Getter is a function which takes a reflect.Value for a slice, and returns a
 * a slice of reflect.Value, e.g. a slice with a reflect.Value for each of the
 * Name fields from a reflect.Value for a slice of a struct type. It is used by
 * the sort functions to identify the elements to sort by.
 * type Getter func(reflect.Value) []reflect.Value
 */
type Getter func(reflect.Value) []reflect.Value

/*
 * Returns a Getter which returns the values from a reflect.Value for a
 * slice. This is the default Getter used if none is passed to Sort.
 */
func SimpleGetter() Getter {
  return func(s reflect.Value) []reflect.Value {
    vals := make([]reflect.Value, s.Len(), s.Len())
    for i := range vals {
      vals[i] = reflect.Indirect(reflect.Indirect(s.Index(i)))
    }
    return vals
  }
}

func (o Ordering) String() string {
  return orderings[o]
}

/*
 * A runtime panic will occur if case-insensitive is used when not sorting by
 * a string type.
 */
const (
  CaseInsensitiveAscending Ordering = iota
)

var orderings = []string{
  "CaseInsensitiveAscending",
}

/* Recognized non-standard types */
var (
  t_time = reflect.TypeOf(time.Time{})
)

/* A reflecting sort.Interface adapter. */
type Sorter struct {
  Slice    reflect.Value
  Getter   Getter
  Ordering Ordering
  /* Type of items being sorted */
  itemType reflect.Type    /* Type of items being sorted */
  /* Nested/child values that we're sorting by */
  vals     []reflect.Value /* Nested/child values that we're sorting by */
}

/* Returns the length of the slice being sorted. */
func (s *Sorter) Len() int {
  return len(s.vals)
}

/* Swaps two indices in the slice being sorted. */
func (s *Sorter) Swap(i, j int) {
  x := s.Slice.Index(i)
  y := s.Slice.Index(j)
  tmp := reflect.New(s.itemType).Elem()
  tmp.Set(x)
  x.Set(y)
  y.Set(tmp)
}

type stringInsensitiveAscending struct{ *Sorter }

func (s stringInsensitiveAscending) Less(i, j int) bool {
  return strings.ToLower(s.Sorter.vals[i].String()) <
                         strings.ToLower(s.Sorter.vals[j].String())
}

/*
 * Returns a Sorter for a slice which will sort according to the
 * items retrieved by getter, in the given ordering.
 */
func New(slice interface{}, getter Getter, ordering Ordering) *Sorter {
  v := reflect.ValueOf(slice)
  return &Sorter{
    Slice:    v,
    Getter:   getter,
    Ordering: ordering,
  }
}

/* Sort a slice in case-insensitive ascending order. */
func CiAsc(slice interface{}) {
  s := New(slice, nil, CaseInsensitiveAscending)
  if s.Getter == nil {
    s.Getter = SimpleGetter()
  }
  if s.Slice.Len() >= 2 {
    s.vals = s.Getter(s.Slice)
    s.itemType = s.Slice.Index(0).Type()
    sort.Sort(stringInsensitiveAscending{s})
  }
}
