package main

import "golang.org/x/sys/windows"

func processStartIdentity() (int64, error) {
	var created, exit, kernel, user windows.Filetime
	err := windows.GetProcessTimes(windows.CurrentProcess(), &created, &exit, &kernel, &user)
	return created.Nanoseconds(), err
}
