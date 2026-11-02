// Package worker holds the Python source for the badkeys worker process.  It
// lives in its own package so it can be unit-tested without triggering the
// badkeys package's init(), which requires a configured badkeys install.
package worker

import (
	"github.com/pkimetal/pkimetal/linter"
	"github.com/pkimetal/pkimetal/linter/pemreader"
)

// Script reads linting requests from STDIN and writes results to STDOUT.  The
// printresults function is adapted from the _printresults function defined by
// https://github.com/badkeys/badkeys/blob/main/badkeys/runcli.py.
const Script = `#!/usr/bin/python3
from sys import stdin
from badkeys.allkeys import urllookup
from badkeys.checks import allchecks, checkcrt

def printresults(key):
	if key["type"] == "unsupported":
		print(f"W: Unsupported key type")
	elif key["type"] == "unparseable":
		print(f"F: Unparseable input")
	elif key["type"] == "notfound":
		print(f"W: No key found")
	else:
		if key["results"] == {}:
			print(f"I: Key ok")
	for check, result in key["results"].items():
		sub = ""
		if "subtest" in result:
			sub = f"/{result['subtest']}"
		if sub.startswith(tuple(["/unusual_keysize", "/exponent_"])):
			print(f"I: {check}{sub}")
		else:
			print(f"E: {check}{sub} vulnerability")

` + pemreader.Reader + `
def exception_finding(e):
	# Report an exception as a single bounded line, so that the response stays in sync.
	return ("F: Exception: " + " ".join(f"{type(e).__name__}: {e}".split()))[:1024]

try:
	for profile_id, pem_data in read_pem_requests(stdin):
		try:
			printresults(checkcrt(pem_data, checks=allchecks))
		except Exception as e:
			print(exception_finding(e))
		print("` + linter.PKIMETAL_ENDOFRESULTS + `", flush=True)
		del pem_data
except KeyboardInterrupt:
	pass
`
