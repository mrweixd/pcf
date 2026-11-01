package processor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/free5gc/openapi/models"
	nfctx "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/sbi/consumer"
)

type terminationPCF struct {
	PCF
	nf   *nfctx.PCFContext
	cons *consumer.Consumer
}

func (a *terminationPCF) Context() *nfctx.PCFContext     { return a.nf }
func (a *terminationPCF) Consumer() *consumer.Consumer   { return a.cons }
func (a *terminationPCF) CancelContext() context.Context { return context.Background() }

func terminationTestH2(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(h)
	s.Config.Protocols = new(http.Protocols)
	s.Config.Protocols.SetHTTP1(true)
	s.Config.Protocols.SetUnencryptedHTTP2(true)
	s.Start()
	t.Cleanup(s.Close)
	return s
}

func TestNEFTerminationAuthorization(t *testing.T) {
	id, caller, issuer := uuid.NewString(), uuid.NewString(), uuid.NewString()
	var calls, tokens, externalHits atomic.Int32
	external := terminationTestH2(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		externalHits.Add(1)
	}))
	endpoint := terminationTestH2(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "Bearer nef-token", r.Header.Get("Authorization"))
		var info models.Pcf_PolAuth_TerminationInfo
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&info))
		assert.Equal(t, "https://pcf.internal/app-sessions/123", info.ResUri)
		calls.Add(1)
		if r.URL.Path == nefTerminationPath+"2/terminate" {
			http.Redirect(w, r, external.URL, http.StatusTemporaryRedirect)
			return
		}
		assert.Equal(t, nefTerminationPath+"1/terminate", r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}))
	nrf := terminationTestH2(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth2/token":
			assert.NoError(t, r.ParseForm())
			token := "disc-token"
			if r.Form.Get("scope") == string(nefCallbackScope) {
				tokens.Add(1)
				assert.Equal(t, "PCF", r.Form.Get("nfType"))
				assert.Equal(t, caller, r.Form.Get("nfInstanceId"))
				assert.Equal(t, "NEF", r.Form.Get("targetNfType"))
				assert.Equal(t, id, r.Form.Get("targetNfInstanceId"))
				token = "nef-token"
			} else {
				assert.Equal(t, "nnrf-disc", r.Form.Get("scope"))
			}
			assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"access_token": token, "token_type": "Bearer", "expires_in": 300, "scope": r.Form.Get("scope"),
			}))
		case "/nnrf-disc/v1/nf-instances":
			assert.Equal(t, "Bearer disc-token", r.Header.Get("Authorization"))
			assert.Equal(t, "NEF", r.URL.Query().Get("target-nf-type"))
			assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{"nfInstances": []any{map[string]any{
				"nfInstanceId": id, "nfType": "NEF", "nfStatus": "REGISTERED", "nfServices": []any{map[string]any{
					"serviceName": nefCallbackScope, "nfServiceStatus": "REGISTERED", "apiPrefix": endpoint.URL,
				}},
			}}}))
		default:
			http.NotFound(w, r)
		}
	}))
	app := &terminationPCF{nf: &nfctx.PCFContext{
		OAuth2Required: true, NfId: caller, NrfNfInstanceID: issuer, NrfUri: nrf.URL,
	}}
	var err error
	app.cons, err = consumer.NewConsumer(app)
	require.NoError(t, err)
	p, err := NewProcessor(app)
	require.NoError(t, err)
	info := &models.Pcf_PolAuth_TerminationInfo{ResUri: "https://pcf.internal/app-sessions/123"}
	require.Error(t, p.sendNEFTermination(external.URL+nefTerminationPath+"1", info))
	require.Zero(t, tokens.Load())
	require.NoError(t, p.sendNEFTermination(endpoint.URL+nefTerminationPath+"1", info))
	require.Error(t, p.sendNEFTermination(endpoint.URL+nefTerminationPath+"2", info))
	require.EqualValues(t, 2, calls.Load())
	require.Zero(t, externalHits.Load())
}

// Invoked by the paired NEF integration test with a local NRF fixture.
func TestPCFTerminationInteropClient(t *testing.T) {
	nrf := os.Getenv("INTEROP_NRF")
	if nrf == "" {
		t.Skip("run from the NEF PCF-termination interop test")
	}
	app := &terminationPCF{nf: &nfctx.PCFContext{
		OAuth2Required: true, NfId: os.Getenv("INTEROP_PCF_ID"),
		NrfUri: nrf, NrfNfInstanceID: os.Getenv("INTEROP_NRF_ID"),
	}}
	var err error
	app.cons, err = consumer.NewConsumer(app)
	require.NoError(t, err)
	p, err := NewProcessor(app)
	require.NoError(t, err)
	uri := os.Getenv("INTEROP_CALLBACK")
	require.True(t, isNEFTerminationURI(uri))
	require.NoError(t, p.sendNEFTermination(uri, &models.Pcf_PolAuth_TerminationInfo{
		ResUri:    os.Getenv("INTEROP_RESOURCE"),
		TermCause: models.Pcf_PolAuth_TerminationCause_PDU_SESSION_TERMINATION,
	}))
}
