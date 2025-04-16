package auth

import (
	"errors"
	"net/http"
	"testing"
)

type TestStruct struct {
	Input    http.Header
	Expected ExpectedStruct
}

type ExpectedStruct struct {
	Value string
	Err   error
}

func makeTestHeader(key string) http.Header {
	header := http.Header{}
	header.Set("Authorization", key)
	return header
}

var tests []TestStruct = []TestStruct{
	TestStruct{
		Input: makeTestHeader("ApiKey Test"),
		Expected: ExpectedStruct{
			Value: "Test",
			Err:   nil,
		},
	},
	TestStruct{
		Input: makeTestHeader(""),
		Expected: ExpectedStruct{
			Value: "",
			Err:   errors.New("no authorization header included"),
		},
	},
	TestStruct{
		Input: makeTestHeader("WrongKey"),
		Expected: ExpectedStruct{
			Value: "",
			Err:   errors.New("malformed authorization header"),
		},
	},
	TestStruct{
		Input: makeTestHeader("ApiKey"),
		Expected: ExpectedStruct{
			Value: "",
			Err:   errors.New("malformed authorization header"),
		},
	},
	TestStruct{
		Input: http.Header{},
		Expected: ExpectedStruct{
			Value: "",
			Err:   errors.New("no authorization header included"),
		},
	},
}

func TestGetAPIKey(t *testing.T) {
	for i, test := range tests {
		k, err := GetAPIKey(test.Input)
		if err != nil {
			if err.Error() != test.Expected.Err.Error() {
				t.Fatalf(`Test: %d
				Expected value: %s
				and error: %v
				but received value: %s
				and error: %v`,
					i,
					test.Expected.Value,
					test.Expected.Err,
					k,
					err,
				)
			}
		}
		if k != test.Expected.Value {
			t.Fail()
		}
	}
}
