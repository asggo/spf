Package spf
===========
import "github.com/averagesecurityguy/spf"

Package spf parses an SPF record and determines if a given IP address
is allowed to send email based on that record. SPF handles all of the
mechanisms defined at http://www.openspf.org/SPF_Record_Syntax.


type Mechanism
--------------
Mechanism represents a single mechanism in an SPF record.

    type Mechanism struct {
	Name   string
	Domain string
	Prefix string
  Result string
    }

func (*Mechanism) String()
-------------------------

    func (m *Mechanism) String() string

Return a Mechanism as a string

func (*Mechanism) ResultTag()
-----------------------------

    func (m *Mechanism) ResultTag() string

Returns the sigil that describes the result of this mechanism (i.e., "+" for "Pass", etc.)

func (m *Mechanism) SPFString()
-------------------------------

    func (m *Mechanism) SPFString() string

Returns a string representation of the mechanism in a format suitable for addition to a SPF record in the DNS.

type SPF
--------
SPF represents an SPF record for a particular Domain. The SPF record
holds all of the mechanisms describing the policy.

    type SPF struct {
        Raw          string
        Domain       string
        Version      string
        Mechanisms   []*Mechanism
    }

func (*SPF) Allowed
-------------------

    func (s *SPF) Allowed(client string) (bool, error)

Determine if an IP address is allowed to send email.

func (*SPF) String
------------------

    func (s *SPF) String() string

Return an SPF record as a string.

func (s *SPF) SPFString()
-------------------------

    func (s *SPF) SPFString() string

Returns a DNS record - compatible representation of the SPF policy described by the SPF object.

func NetworkCIDR
----------------

    func NetworkCIDR(addr, prefix string) (*net.IPNet, error)

Create a new net.IPNet object using the given IP address and mask.

func NewMechanism
-----------------

    func NewMechanism(str, domain string) *Mechanism

NewMechanism creates a new Mechanism struct using the given string and
domain name. When the mechanism does not define the domain, the provided
domain is used as the default.

func NewSPFDomain
-----------------

    func NewSPFDomain(domain string) (*SPF, error)

Create a new SPF record using a domain name. If no SPF record is found
for the given domain an error is returned.

func NewSPFString
-----------------

    func NewSPFString(domain, record string) (*SPF, error)

Create a new SPF record for the given domain using the provided string.
If the provided string is not valid an error is returned.
