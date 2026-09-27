package main

// Exit codes are distinct so a pipeline can tell a leak from a broken scan.
// Conflating them is a real bug in other scanners: a run that failed on a
// permission error looks exactly like a clean one, and the failure goes
// unnoticed for months.
const (
	exitClean    = 0
	exitError    = 1
	exitFindings = 3
)
