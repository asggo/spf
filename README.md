# Package spf

[![Documentation](https://godoc.org/github.com/asggo/spf?status.svg)](http://godoc.org/github.com/asggo/spf)

Package spf parses an SPF record and determines if a given IP address
is allowed to send email based on that record. SPF handles all of the
mechanisms defined at http://www.open-spf.org/SPF_Record_Syntax/.

## Example

```Go
package main

import "github.com/asggo/spf"

func main() {

        SMTPClientIP := "1.1.1.1"
        envelopeFrom := "info@example.com"

        result, err := spf.SPFTest(SMTPClientIP, envelopeFrom)
        if err != nil {
                panic(err)
        }

        switch result {
        case spf.Pass:
                // allow action
        case spf.Fail:
                // deny action
        }
	//...
}

```
