package main

import (
	"io"
	"time"
)

const progressTick = 100 * time.Millisecond

// countingWriter wraps an io.Writer and tallies bytes written. onTick, if
// set, fires at most every progressTick with the running byte count  used
// to surface streaming progress when the total size isn't known up front.
type countingWriter struct {
	w      io.Writer
	n      int64
	last   time.Time
	onTick func(n int64)
}

func (c *countingWriter) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)

	c.n += int64(n)
	if c.onTick != nil && n > 0 {
		if now := time.Now(); now.Sub(c.last) >= progressTick {
			c.last = now
			c.onTick(c.n)
		}
	}

	return n, err
}
