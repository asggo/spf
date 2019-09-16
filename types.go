package spf

import "errors"

// Mechanism represents a single mechanism in an SPF record.
type Mechanism struct {
	Name   string
	Domain string
	Prefix string
	Result string
}

// SPF represents an SPF record for a particular Domain. The SPF record
// holds all of the Allow, Deny, and Neutral mechanisms.
type SPF struct {
	Raw        string
	Domain     string
	Version    string
	Mechanisms []*Mechanism
}

// ErrPermFail is a special error triggered by malformed SPF records as per
// RFC-7208 § 4.6
var ErrPermFail = errors.New("ErrPermFail: Invalid SPF record")
