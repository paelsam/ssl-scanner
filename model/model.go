package model

type Info struct {
	Version              string   `json:"version"`
	CriteriaVersion      string   `json:"criteriaVersion"`
	MaxAssessments       int      `json:"maxAssessments"`
	CurrentAssessments   int      `json:"currentAssessments"`
	NewAssessmentCoolOff int64    `json:"newAssessmentCoolOff"`
	Messages             []string `json:"messages"`
}

type Host struct {
	Host            string     `json:"host"`
	Port            int        `json:"port"`
	Protocol        string     `json:"protocol"`
	IsPublic        bool       `json:"isPublic"`
	Status          string     `json:"status"`
	StatusMessage   string     `json:"statusMessage"`
	StartTime       int64      `json:"startTime"`
	TestTime        int64      `json:"testTime"`
	EngineVersion   string     `json:"engineVersion"`
	CriteriaVersion string     `json:"criteriaVersion"`
	Endpoints       []Endpoint `json:"endpoints"`
	CertHostnames   []string   `json:"certHostnames"`
}

type Endpoint struct {
	IPAddress            string           `json:"ipAddress"`
	ServerName           string           `json:"serverName"`
	StatusMessage        string           `json:"statusMessage"`
	StatusDetails        string           `json:"statusDetails"`
	StatusDetailsMessage string           `json:"statusDetailsMessage"`
	Grade                string           `json:"grade"`
	GradeTrustIgnored    string           `json:"gradeTrustIgnored"`
	HasWarnings          bool             `json:"hasWarnings"`
	IsExceptional        bool             `json:"isExceptional"`
	Progress             int              `json:"progress"`
	Duration             int64            `json:"duration"`
	ETA                  int              `json:"eta"`
	Delegation           int              `json:"delegation"`
	Details              *EndpointDetails `json:"details,omitempty"`
}

type EndpointDetails struct {
	HostStartTime      int64       `json:"hostStartTime"`
	Key                *Key        `json:"key,omitempty"`
	Cert               *Cert       `json:"cert,omitempty"`
	Chain              *Chain      `json:"chain,omitempty"`
	Protocols          []Protocol  `json:"protocols"`
	Suites             *Suites     `json:"suites,omitempty"`
	ServerSignature    string      `json:"serverSignature"`
	VulnBeast          bool        `json:"vulnBeast"`
	RenegSupport       int         `json:"renegSupport"`
	SessionResumption  int         `json:"sessionResumption"`
	CompressionMethods int         `json:"compressionMethods"`
	SupportsNpn        bool        `json:"supportsNpn"`
	NpnProtocols       string      `json:"npnProtocols"`
	SessionTickets     int         `json:"sessionTickets"`
	OcspStapling       bool        `json:"ocspStapling"`
	SniRequired        bool        `json:"sniRequired"`
	HTTPStatusCode     int         `json:"httpStatusCode"`
	HTTPForwarding     string      `json:"httpForwarding"`
	SupportsRC4        bool        `json:"supportsRc4"`
	RC4WithModern      bool        `json:"rc4WithModern"`
	RC4Only            bool        `json:"rc4Only"`
	ForwardSecrecy     int         `json:"forwardSecrecy"`
	Heartbleed         bool        `json:"heartbleed"`
	Heartbeat          bool        `json:"heartbeat"`
	OpenSSLCcs         int         `json:"openSslCcs"`
	Poodle             bool        `json:"poodle"`
	PoodleTLS          int         `json:"poodleTls"`
	FallbackScsv       bool        `json:"fallbackScsv"`
	Freak              bool        `json:"freak"`
	HasSct             int         `json:"hasSct"`
	DhPrimes           []string    `json:"dhPrimes"`
	DhUsesKnownPrimes  int         `json:"dhUsesKnownPrimes"`
	DhYsReuse          bool        `json:"dhYsReuse"`
	Logjam             bool        `json:"logjam"`
	ChaCha20Preference bool        `json:"chaCha20Preference"`
	HstsPolicy         *HstsPolicy `json:"hstsPolicy,omitempty"`
}

type Key struct {
	Size       int    `json:"size"`
	Strength   int    `json:"strength"`
	Alg        string `json:"alg"`
	DebianFlaw bool   `json:"debianFlaw"`
	Q          *int   `json:"q"`
}

type Cert struct {
	Subject          string   `json:"subject"`
	CommonNames      []string `json:"commonNames"`
	AltNames         []string `json:"altNames"`
	NotBefore        int64    `json:"notBefore"`
	NotAfter         int64    `json:"notAfter"`
	IssuerSubject    string   `json:"issuerSubject"`
	SigAlg           string   `json:"sigAlg"`
	IssuerLabel      string   `json:"issuerLabel"`
	RevocationInfo   int      `json:"revocationInfo"`
	CrlURIs          []string `json:"crlURIs"`
	OcspURIs         []string `json:"ocspURIs"`
	RevocationStatus int      `json:"revocationStatus"`
	SGC              int      `json:"sgc"`
	ValidationType   string   `json:"validationType"`
	Issues           int      `json:"issues"`
	SCT              bool     `json:"sct"`
}

type Chain struct {
	Certs  []ChainCert `json:"certs"`
	Issues int         `json:"issues"`
}

type ChainCert struct {
	Subject              string `json:"subject"`
	Label                string `json:"label"`
	NotBefore            int64  `json:"notBefore"`
	NotAfter             int64  `json:"notAfter"`
	IssuerSubject        string `json:"issuerSubject"`
	IssuerLabel          string `json:"issuerLabel"`
	SigAlg               string `json:"sigAlg"`
	Issues               int    `json:"issues"`
	KeyAlg               string `json:"keyAlg"`
	KeySize              int    `json:"keySize"`
	KeyStrength          int    `json:"keyStrength"`
	RevocationStatus     int    `json:"revocationStatus"`
	CrlRevocationStatus  int    `json:"crlRevocationStatus"`
	OcspRevocationStatus int    `json:"ocspRevocationStatus"`
	Raw                  string `json:"raw"`
}

type Protocol struct {
	ID               int    `json:"id"`
	Name             string `json:"name"`
	Version          string `json:"version"`
	V2SuitesDisabled bool   `json:"v2SuitesDisabled"`
	Q                *int   `json:"q"`
}

type Suites struct {
	List       []Suite `json:"list"`
	Preference bool    `json:"preference"`
}

type Suite struct {
	ID             int    `json:"id"`
	Name           string `json:"name"`
	CipherStrength int    `json:"cipherStrength"`
	DhStrength     int    `json:"dhStrength"`
	DhP            int    `json:"dhP"`
	DhG            int    `json:"dhG"`
	DhYs           int    `json:"dhYs"`
	EcdhBits       int    `json:"ecdhBits"`
	EcdhStrength   int    `json:"ecdhStrength"`
	Q              *int   `json:"q"`
}

type HstsPolicy struct {
	Header            string      `json:"header"`
	Status            string      `json:"status"`
	Error             string      `json:"error"`
	MaxAge            int64       `json:"maxAge"`
	IncludeSubDomains bool        `json:"includeSubDomains"`
	Preload           bool        `json:"preload"`
	Directives        interface{} `json:"directives"`
}

type APIError struct {
	Errors []ErrorDetail `json:"errors"`
}

type ErrorDetail struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}
