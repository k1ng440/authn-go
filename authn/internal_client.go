package authn

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	jose "gopkg.in/square/go-jose.v2"
)

type internalClient struct {
	baseURL *url.URL
	http    http.Client
	auth    struct {
		username, password string
	}
}

// HTTP methods we support
const (
	post    = "POST"
	get     = "GET"
	head    = "HEAD"
	put     = "PUT"
	delete  = "DELETE"
	patch   = "PATCH"
	options = "OPTIONS"
)

func newInternalClient(base, username, password string) (*internalClient, error) {
	// ensure that base ends with a '/', so ResolveReference() will work as desired
	if base[len(base)-1] != '/' {
		base = base + "/"
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return nil, err
	}

	ic := internalClient{
		baseURL: baseURL,
		http: http.Client{
			Timeout: 5 * time.Second,
		},
	}

	return &ic, nil
}

// TODO: test coverage
func (ic *internalClient) Key(kid string) ([]jose.JSONWebKey, error) {
	resp, err := http.Get(ic.absoluteURL("jwks"))
	if err != nil {
		return []jose.JSONWebKey{}, err
	}
	defer resp.Body.Close()

	if !isStatusSuccess(resp.StatusCode) {
		return []jose.JSONWebKey{}, fmt.Errorf("Received %d from %s", resp.StatusCode, ic.absoluteURL("jwks"))
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []jose.JSONWebKey{}, err
	}

	jwks := &jose.JSONWebKeySet{}

	err = json.Unmarshal(bodyBytes, jwks)
	if err != nil {
		return []jose.JSONWebKey{}, err
	}
	return jwks.Key(kid), nil
}

func (ic *internalClient) absoluteURL(path string) string {
	return ic.baseURL.ResolveReference(&url.URL{Path: path}).String()
}

func (ic *internalClient) newRequest(method string, path string, reqBody []byte) (*http.Response, []byte, error) {
	var b io.Reader
	if cap(reqBody) > 0 {
		b = bytes.NewReader(reqBody)
	}

	req, err := http.NewRequest(method, ic.absoluteURL(path), b)
	if err != nil {
		return nil, nil, err
	}

	if ic.auth != struct{ username, password string }{} {
		req.SetBasicAuth(ic.auth.username, ic.auth.password)
	}

	resp, err := ic.http.Do(req)
	if err != nil {
		return nil, nil, err
	}

	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	// Reset resp.Body so it can be use again
	resp.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	return resp, body, nil

}

// unused. this will eventually execute private admin actions.
func (ic *internalClient) get(path string, dest interface{}) (int, error) {
	resp, body, err := ic.newRequest(get, path, make([]byte, 0))
	if err != nil {
		return -1, err
	}

	err = json.Unmarshal(body, dest)
	if err != nil {
		return resp.StatusCode, err
	}
	return resp.StatusCode, nil
}

func (ic *internalClient) post(path string, data []byte, dest interface{}) (int, error) {
	resp, body, err := ic.newRequest(post, path, make([]byte, 0))
	if err != nil {
		return -1, err
	}

	err = json.Unmarshal(body, dest)
	if err != nil {
		return resp.StatusCode, err
	}
	return resp.StatusCode, nil
}

func (ic *internalClient) patch(path string, data []byte) (int, error) {
	resp, _, err := ic.newRequest(patch, path, make([]byte, 0))
	if err != nil {
		return -1, err
	}

	return resp.StatusCode, nil
}

func (ic *internalClient) delete(path string) (int, error) {
	resp, _, err := ic.newRequest(delete, path, make([]byte, 0))
	if err != nil {
		return -1, err
	}

	return resp.StatusCode, nil
}

func isStatusSuccess(statusCode int) bool {
	return statusCode >= 200 && statusCode < 300
}
