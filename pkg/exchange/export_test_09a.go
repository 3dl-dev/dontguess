package exchange

// export_test_09a.go — read-only accessors for the dontguess-4c1 credit-terms
// invariant. Deliberately a normal file, not _test.go: the assertion lives in
// cmd/dontguess (where the rest of the credit/admission tests are) and needs to
// read these package-private constants.

// CreditLoanVigRateBPSForTest exposes the recorded vig rate for invariant tests.
func CreditLoanVigRateBPSForTest() int64 { return creditLoanVigRateBPS }

// CreditLoanTermDaysForTest exposes the recorded loan term for invariant tests.
func CreditLoanTermDaysForTest() int64 { return creditLoanTermDays }
