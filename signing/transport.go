package signing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	signer "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

var (
	MissingSigner  = errors.New("signer is required to perform http request")
	MissingService = errors.New("aws service is required to perform http request")
	MissingRegion  = errors.New("aws region is required to perform http request")
)

// Signer represents an interface that v1 and v2 aws sdk follows to sign http requests
type Signer interface {
	SignHTTP(ctx context.Context, credentials aws.Credentials, r *http.Request, payloadHash string, service string, region string, signingTime time.Time, optFns ...func(options *signer.SignerOptions)) error
}

// Creates a new transport that can be used by http.Client
// If region is unspecified, AWS_REGION environment variable is used
func NewTransport(signer Signer, credentials aws.Credentials, service, region string) *Transport {
	return &Transport{
		signer:      signer,
		credentials: credentials,
		service:     service,
		region:      region,
	}
}

// Transport implements http.RoundTripper and optionally wraps another RoundTripper
type Transport struct {
	BaseTransport http.RoundTripper
	signer        Signer
	credentials   aws.Credentials
	service       string
	region        string
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.signer == nil {
		return nil, MissingSigner
	}
	if t.service == "" {
		return nil, MissingService
	}
	if t.region == "" {
		return nil, MissingRegion
	}

	baseTransport := t.BaseTransport
	if baseTransport == nil {
		baseTransport = http.DefaultTransport
	}
	if h, ok := req.Header["Authorization"]; ok && len(h) > 0 && strings.HasPrefix(h[0], "AWS4") {
		return baseTransport.RoundTrip(req)
	}

	if err := t.sign(req); err != nil {
		return nil, fmt.Errorf("error signing request: %s", err)
	}
	return baseTransport.RoundTrip(req)
}

func (t *Transport) sign(req *http.Request) error {
	req.URL.Scheme = "https"
	if strings.Contains(req.URL.RawPath, "%2C") {
		req.URL.RawPath = escapePath(req.URL.RawPath, false)
	}

	// AWS forbids signed requests that are forwarded, drop headers
	req.Header.Del("X-Forwarded-For")
	req.Header.Del("X-Forwarded-Host")
	req.Header.Del("X-Forwarded-Port")
	req.Header.Del("X-Forwarded-Proto")

	date := time.Now()
	req.Header.Set("Date", date.Format(time.RFC3339))

	hash, err := t.rebuildBody(req)
	if err != nil {
		return err
	}
	// PayloadHash is the hex encoded SHA-256 hash of the request payload
	if err := t.signer.SignHTTP(req.Context(), t.credentials, req, string(hash), t.service, t.region, date); err != nil {
		return fmt.Errorf("error signing request: %s", err)
	}
	return nil
}

func (t *Transport) rebuildBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		sum := sha256.Sum256(nil)
		return sum[:], nil
	}

	d, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading http body to sign: %s", err)
	}
	req.Body = ioutil.NopCloser(bytes.NewReader(d))
	sum := sha256.Sum256(d)
	return sum[:], nil
}
