package manager

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net/http"
	"os"
	"syscall"

	"github.com/zeroemployeeorg/pomar/internal/artifactreturn"
)

// ReceiveArtifacts authenticates the original raw result before fetching any
// files, then returns only an entire verified staged set. The binding and key
// come independently from the receiving owner. No job is started or retried.
// Legacy Output remains separate and is not whole-artifact acceptance.
func (c *Client) ReceiveArtifacts(ctx context.Context, parent *os.Root, id string, key ed25519.PublicKey, want artifactreturn.Expected) (string, error) {
	dir, e := parent.Open(".")
	if e != nil {
		return "", e
	}
	info, e := dir.Stat()
	dir.Close()
	if e != nil {
		return "", e
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || owner.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 {
		return "", fmt.Errorf("manager: artifact destination requires a private owner directory")
	}
	if id != want.Attempt || !artifactreturn.ValidName(id) {
		return "", fmt.Errorf("manager: artifact attempt binding mismatch")
	}
	client := *c.http
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	control, cancel := context.WithTimeout(ctx, CallBound)
	request, err := http.NewRequestWithContext(control, "GET", "http://manager/v1/attempts/"+id+"/result", nil)
	if err != nil {
		cancel()
		return "", err
	}
	request.Close = true
	response, err := client.Do(request)
	if err != nil {
		cancel()
		return "", err
	}
	if response.StatusCode != http.StatusOK || response.ContentLength > artifactreturn.MaxResultBytes {
		response.Body.Close()
		cancel()
		return "", fmt.Errorf("manager: original artifact result unavailable or over limit")
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, artifactreturn.MaxResultBytes+1))
	closeErr := response.Body.Close()
	cancel()
	if readErr != nil {
		return "", readErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	verified, err := artifactreturn.Verify(raw, key, want)
	if err != nil {
		return "", err
	}
	outputs := map[string]artifactreturn.Output{}
	for _, output := range verified.Outputs {
		outputs[output.Name] = output
	}
	fetch := func(transfer context.Context, name string) (io.ReadCloser, error) {
		output, ok := outputs[name]
		if !ok {
			return nil, fmt.Errorf("manager: output outside signed set")
		}
		req, e := http.NewRequestWithContext(transfer, "GET", "http://manager/v1/attempts/"+id+"/outputs/"+name, nil)
		if e != nil {
			return nil, e
		}
		req.Close = true
		reply, e := client.Do(req)
		if e != nil {
			return nil, e
		}
		if reply.StatusCode != http.StatusOK || reply.ContentLength != output.Bytes || reply.Header.Get(OutputSHA256Header) != output.SHA256 {
			reply.Body.Close()
			return nil, fmt.Errorf("manager: artifact response metadata differs from original signed result")
		}
		return reply.Body, nil
	}
	return artifactreturn.Receive(ctx, parent, raw, key, want, fetch, nil)
}
