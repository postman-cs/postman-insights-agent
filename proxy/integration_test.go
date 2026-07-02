package proxy_test

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pb "github.com/akitasoftware/akita-ir/go/api_spec"
	"github.com/akitasoftware/akita-libs/akid"
	kgxapi "github.com/akitasoftware/akita-libs/api_schema"
	"github.com/akitasoftware/akita-libs/buffer_pool"
	"github.com/akitasoftware/akita-libs/spec_util"
	"github.com/akitasoftware/akita-libs/tags"
	"github.com/akitasoftware/go-utils/optionals"
	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/proto"
	"github.com/postmanlabs/postman-insights-agent/apispec"
	"github.com/postmanlabs/postman-insights-agent/data_masks"
	"github.com/postmanlabs/postman-insights-agent/proxy"
	"github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/postmanlabs/postman-insights-agent/telemetry"
	"github.com/postmanlabs/postman-insights-agent/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// End-to-end through the real pipeline: proxy capture -> redaction ->
// backend collector pairing -> witness upload payload. This is the same
// path production traffic takes; only the HTTP transport to the Postman
// backend is mocked.
func TestProxyThroughBackendCollector(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	uploaded := make(chan *pb.Witness, 16)
	mockClient := rest.NewMockLearnClient(ctrl)
	mockClient.
		EXPECT().
		AsyncReportsUpload(gomock.Any(), gomock.Any(), gomock.Any()).
		Do(func(args ...interface{}) {
			reports := args[2].(*kgxapi.UploadReportsRequest)
			for _, r := range reports.Witnesses {
				bs, err := base64.URLEncoding.DecodeString(r.WitnessProto)
				require.NoError(t, err)
				w := &pb.Witness{}
				require.NoError(t, proto.Unmarshal(bs, w))
				uploaded <- w
			}
		}).
		AnyTimes().
		Return(nil)
	mockClient.
		EXPECT().
		GetDynamicAgentConfigForService(gomock.Any(), gomock.Any()).
		AnyTimes().
		Return(kgxapi.NewServiceAgentConfig(), nil)

	svc := akid.GenerateServiceID()
	lrn := akid.GenerateLearnSessionID()

	redactor, err := data_masks.NewRedactor(svc, mockClient)
	require.NoError(t, err)

	col := trace.NewBackendCollector(
		svc,
		map[tags.Key]string{},
		lrn,
		mockClient,
		redactor,
		optionals.None[int](),
		trace.NewPacketCounter(),
		false,
		optionals.None[[]string](),
		nil,
		apispec.DefaultMaxWintessUploadBuffers,
		telemetry.Default(),
	)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "{\"id\": 42, \"status\": \"created\"}")
	}))
	defer upstream.Close()

	pool, err := buffer_pool.MakeBufferPool(16*1024*1024, 4*1024)
	require.NoError(t, err)

	p, err := proxy.New(proxy.Args{
		ListenAddr:          "127.0.0.1:0",
		Upstream:            mustParseURL(t, upstream.URL),
		UpstreamTLSInsecure: true,
	}, col, pool)
	require.NoError(t, err)
	stop := make(chan struct{})
	go p.Serve(stop)
	defer close(stop)

	const secret = "proxy-e2e-super-secret-key-value"
	req, err := http.NewRequest("POST", "http://"+p.Addr().String()+"/v1/pets",
		strings.NewReader("{\"name\": \"rex\", \"species\": \"dog\"}"))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", secret)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Flush the pipeline.
	require.NoError(t, col.Close())

	var w *pb.Witness
	select {
	case w = <-uploaded:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for witness upload")
	}

	meta := spec_util.HTTPMetaFromMethod(w.Method)
	require.NotNil(t, meta, "uploaded witness should carry HTTP metadata")
	assert.Equal(t, "POST", meta.GetMethod())
	assert.Equal(t, "/v1/pets", meta.GetPathTemplate())

	// The request (args) and response sections must both be present: proves
	// the two halves of the proxied exchange were paired into one witness.
	assert.NotEmpty(t, w.Method.GetArgs(), "request fields missing from witness")
	assert.NotEmpty(t, w.Method.GetResponses(), "response fields missing from witness")

	// The sensitive header value must not survive redaction anywhere in the
	// uploaded payload.
	assert.NotContains(t, proto.MarshalTextString(w), secret,
		"sensitive header value leaked into uploaded witness")
}
