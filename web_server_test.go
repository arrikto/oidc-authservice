package main

import (
	"net/http"
	"testing"
	"time"

	"github.com/arrikto/oidc-authservice/common"
)

func TestWebServerDefault(t *testing.T) {
	s := &WebServer{
		TemplatePaths: []string{"web/templates/default"},
		ProviderURL:   "http://example.test",
		ClientName:    "Kubeflow",
		ThemeURL:      "themes/kubeflow",
		Frontend:      map[string]string{},
	}
	// Start web server
	go func() {
		t.Fatal(s.Start("localhost:8082"))
	}()
	time.Sleep(3 * time.Second)
	baseURL := common.MustParseURL("http://localhost:8082")
	homepage := baseURL.ResolveReference(common.MustParseURL("/site/homepage"))
	afterLogout := baseURL.ResolveReference(common.MustParseURL("/site/after_logout"))
	image := baseURL.ResolveReference(common.MustParseURL("/site/themes/kubeflow/styles.css"))

	tests := []struct {
		name string
		url  string
	}{
		{name: "homepage", url: homepage.String()},
		{name: "afterLogout", url: afterLogout.String()},
		{name: "image", url: image.String()},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resp, err := http.DefaultClient.Get(test.url)
			if err != nil {
				t.Fatalf("Error making http request: %v", err)
			}
			if resp.StatusCode != 200 {
				t.Fatalf("Got non-200 status code: %v", resp.StatusCode)
			}
		})
	}
}
