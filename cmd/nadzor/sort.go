package main

import "sort"

func sortStrings(s []string) { sort.Strings(s) }

func sortFiles(f []transcriptFile) {
	sort.Slice(f, func(i, j int) bool { return f[i].path < f[j].path })
}
