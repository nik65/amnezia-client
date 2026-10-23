//go:build !windows

package main

import "errors"

func processStartIdentity() (int64, error) { return 0, errors.New("Windows guest only") }
