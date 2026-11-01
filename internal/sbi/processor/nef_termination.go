package processor

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/nrf/NFDisc"
	"github.com/free5gc/openapi/pcf/PolAuth"
)

const (
	nefCallbackScope   = "nnef-callback"
	nefTerminationPath = "/nnef-callback/v1/notification/pcf/"
)

func isNEFTerminationURI(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && strings.Contains(u.Path, nefTerminationPath)
}

// Match the absolute callback to the NEF service API root returned by the NRF.
// A path supplied in an app-session request alone never authorizes token delivery.
func terminationOwner(uri string, profiles []models.Nrf_NFDisc_NFProfile) (string, error) {
	u, err := url.Parse(uri)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" {
		return "", fmt.Errorf("invalid NEF callback URI")
	}
	_, id, ok := strings.Cut(u.Path, nefTerminationPath)
	if !ok || id == "" || strings.Trim(id, "0123456789") != "" {
		return "", fmt.Errorf("invalid NEF callback correlation ID")
	}
	owner := ""
	for _, nf := range profiles {
		if nf.NfType != models.Nrf_NFMgmt_NFType_NEF || nf.NfStatus != models.Nrf_NFMgmt_NFStatus_REGISTERED ||
			nf.NfInstanceId == "" {
			continue
		}
		match := func(s models.Nrf_NFDisc_NFService) bool {
			return s.ServiceName == nefCallbackScope && s.NfServiceStatus == models.Nrf_NFMgmt_NFServiceStatus_REGISTERED &&
				strings.TrimSuffix(s.ApiPrefix, "/")+nefTerminationPath+id == uri
		}
		found := false
		for _, s := range nf.NfServices {
			found = found || match(s)
		}
		for _, s := range nf.NfServiceList {
			found = found || match(s)
		}
		if found {
			if owner != "" && owner != nf.NfInstanceId {
				return "", fmt.Errorf("ambiguous NEF callback owner")
			}
			owner = nf.NfInstanceId
		}
	}
	if owner == "" {
		return "", fmt.Errorf("unregistered NEF callback endpoint")
	}
	return owner, nil
}

type terminationConfig struct{ *PolAuth.Configuration }

func (terminationConfig) RedirectPolicy() openapi.RedirectPolicy { return openapi.RejectRedirects }

func (p *Processor) sendNEFTermination(uri string, info *models.Pcf_PolAuth_TerminationInfo) error {
	nf := p.Context()
	// The NEF callback carries internal session identifiers even with OAuth off.
	result, err := p.Consumer().SendSearchNFInstances(
		nf.NrfUri, models.Nrf_NFMgmt_NFType_NEF, models.Nrf_NFMgmt_NFType_PCF,
		NFDisc.SearchNFInstancesRequest{ServiceNames: []models.Nrf_NFMgmt_ServiceName{nefCallbackScope}})
	if err != nil {
		return err
	}
	owner, err := terminationOwner(uri, result.NfInstances)
	if err != nil {
		return err
	}
	ctx, _, err := nf.GetTokenCtxForNFInstance(nefCallbackScope, models.Nrf_NFMgmt_NFType_NEF, owner)
	if err != nil {
		return err
	}
	cfg := terminationConfig{PolAuth.NewConfiguration()}
	req, err := openapi.PrepareRequest(ctx, cfg, uri+"/terminate", http.MethodPost, info,
		map[string]string{"Content-Type": "application/json"}, nil, nil, "", "", nil)
	if err != nil {
		return err
	}
	resp, err := openapi.CallAPI(cfg, req)
	if err != nil {
		return err
	}
	if err := resp.Body.Close(); err != nil {
		return err
	}
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("NEF termination returned HTTP %d", resp.StatusCode)
	}
	return nil
}
