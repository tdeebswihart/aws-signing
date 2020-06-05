package signing

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

var (
	MissingSigner  = errors.New("signer is required to perform http request")
	MissingService = errors.New("aws service is required to perform http request")
	MissingRegion  = errors.New("aws region is required to perform http request")
)

// Signer represents an interface that v1 and v2 aws sdk follows to sign http requests
type Signer interface {
	Sign(ctx context.Context, r *http.Request, body io.ReadSeeker, service, region string, signTime time.Time) (http.Header, error)
}

// Creates a new transport that can be used by http.Client
// If region is unspecified, AWS_REGION environment variable is used
func NewTransport(signer Signer, service, region string) *Transport {
	return &Transport{
		signer:  signer,
		service: service,
		region:  region,
	}
}

// Transport implements http.RoundTripper and optionally wraps another RoundTripper
type Transport struct {
	BaseTransport http.RoundTripper
	signer        Signer
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

	if body, err := t.rebuildBody(req); err != nil {
		return err
	} else if _, err := t.signer.Sign(req.Context(), req, body, t.service, t.region, date); err != nil {
		return fmt.Errorf("error signing request: %s", err)
	}
	return nil
}

func (t *Transport) rebuildBody(req *http.Request) (io.ReadSeeker, error) {
	if req.Body == nil {
		return nil, nil
	}

	d, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading http body to sign: %s", err)
	}
	req.Body = ioutil.NopCloser(bytes.NewReader(d))
	return bytes.NewReader(d), nil
}
