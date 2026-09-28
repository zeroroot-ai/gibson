// Package client is an analyzer-fixture stub of the real
// github.com/openfga/go-sdk/client package: just the two tuple-key type
// aliases the tenantrolewrite guard matches by their underlying names.
package client

import openfga "github.com/openfga/go-sdk"

// ClientTupleKey is a type alias in the real SDK too, not a distinct named
// type — the guard matches its underlying name (openfga.TupleKey).
type ClientTupleKey = openfga.TupleKey

// ClientTupleKeyWithoutCondition is a type alias in the real SDK too.
type ClientTupleKeyWithoutCondition = openfga.TupleKeyWithoutCondition
