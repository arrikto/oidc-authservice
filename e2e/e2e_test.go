// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	appsv1 "k8s.io/api/apps/v1"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	controllerruntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// testclient is an HTTP client that:
// - Doesn't follow redirects
// - Doesn't verify TLS
//
// Useful for testing purposes.
var testClient = &http.Client{
	// Don't follow redirects automatically
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			// Allow self-signed CAs for tests only
			InsecureSkipVerify: true,
		},
	},
}

type E2ETestSuite struct {
	suite.Suite
	kubeclient   client.Client
	kubeclientgo *kubernetes.Clientset
	appURL       *url.URL
	username     string
	password     string
	stopCh       chan struct{}
}

func TestE2ETestSuite(t *testing.T) {
	suite.Run(t, new(E2ETestSuite))
}

func (suite *E2ETestSuite) SetupSuite() {
	suite.stopCh = make(chan struct{})

	log.Info("Creating K3D Cluster...")
	suite.Require().Nil(createK3DCluster())

	log.Info("Applying kustomizations...")
	kustomizations := []string{
		"manifests/istio-1-6-0/base",
		"manifests/protected-workload/base",
		"manifests/dex/overlays/e2e",
		"manifests/authservice/base",
	}
	suite.Require().Nil(applyKustomizations(kustomizations))

	log.Info("Waiting for everything to become ready...")
	restConfig, err := controllerruntime.GetConfig()
	suite.Require().Nil(err)
	kubeclient, err := client.New(restConfig, client.Options{})
	suite.Require().Nil(err)
	suite.kubeclient = kubeclient
	suite.kubeclientgo = kubernetes.NewForConfigOrDie(restConfig)

	timeout := time.Minute
	period := 5 * time.Second
	suite.Require().Nil(
		waitForDeployment(suite.kubeclient, "istio-system", "istiod", timeout, period))
	suite.Require().Nil(
		waitForDeployment(suite.kubeclient, "istio-system", "istio-ingressgateway", timeout, period))
	suite.Require().Nil(
		waitForDeployment(suite.kubeclient, "auth", "dex", timeout, period))
	suite.Require().Nil(
		waitForDeployment(suite.kubeclient, "kubeflow", "workload", timeout, period))
	suite.Require().Nil(
		waitForStatefulSet(suite.kubeclient, "istio-system", "authservice", timeout, period))

	suite.appURL = mustParseURL("http://127.0.0.1:8080/")
	suite.username = "user"
	suite.password = "12341234"

}

func (suite *E2ETestSuite) TearDownSuite() {
	suite.Require().Nil(deleteK3DCluster())
}

func (suite *E2ETestSuite) TestKubernetesLogin() {
	// Port-forward the istio-ingressgateway for this test
	go func() {
		suite.T().Log("Starting port-forward...")
		err := portForward("service", "istio-system", "istio-ingressgateway", "8080", "80", suite.stopCh)
		if err != nil {
			log.Fatalf("Port-forward failed: %+v", err)
		}
	}()
	time.Sleep(2 * time.Second)
	defer func() {
		suite.T().Log("Stopping port-forward...")
		suite.stopCh <- struct{}{}
		time.Sleep(2 * time.Second)
	}()

	suite.T().Log("Testing Kubernetes login...")

	suite.T().Log("Doing TokenRequest...")
	exp := int64(3600)
	tr := &authv1.TokenRequest{
		Spec: authv1.TokenRequestSpec{
			Audiences:         []string{"istio-ingressgateway.istio-system.svc.cluster.local"},
			ExpirationSeconds: &exp,
		},
	}
	ctx := context.Background()

	tr, err := suite.kubeclientgo.CoreV1().ServiceAccounts("default").CreateToken(ctx, "default", tr, metav1.CreateOptions{})
	suite.Require().NoError(err, "TokenRequest failed")

	suite.T().Log("Making HTTP request with ServiceAccountToken...")
	req, err := http.NewRequest(http.MethodGet, suite.appURL.String(), nil)
	suite.Require().NoError(err, "Failed to create request")
	token := tr.Status.Token
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

	httpClient := testClient
	resp, err := httpClient.Do(req)
	suite.Require().NoError(err, "HTTP request with k8s auth failed")
	suite.Require().Equal(http.StatusOK, resp.StatusCode, "Unexpected return code")
}

func (suite *E2ETestSuite) TestLogout() {

	go func() {
		suite.T().Log("Starting port-forward...")
		err := portForward("service", "istio-system", "istio-ingressgateway", "8080", "80", suite.stopCh)
		if err != nil {
			log.Fatalf("Port-forward failed: %+v", err)
		}
	}()
	time.Sleep(2 * time.Second)
	defer func() {
		suite.T().Log("Stopping port-forward...")
		suite.stopCh <- struct{}{}
		time.Sleep(2 * time.Second)
	}()

	t := suite.T()
	httpClient := testClient

	// Login and get cookie in order to logout next
	cookie := login(t, suite.appURL, suite.username, suite.password)

	// Cookie authentication should fail
	logoutURL := suite.appURL.ResolveReference(mustParseURL("/authservice/logout"))
	req, err := http.NewRequest(http.MethodPost, logoutURL.String(), nil)
	require.Nil(t, err)
	req.Header.Set("Cookie", cookie)
	resp, err := httpClient.Do(req)
	require.Nil(t, err)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Header authentication should succeed
	req, err = http.NewRequest(http.MethodPost, logoutURL.String(), nil)
	require.Nil(t, err)
	bearer := strings.TrimSpace(strings.Split(cookie, "=")[1])
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", bearer))
	resp, err = httpClient.Do(req)
	require.Nil(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// User should be logged out now
	req, err = http.NewRequest(http.MethodGet, suite.appURL.String(), nil)
	require.Nil(t, err)
	req.Header.Set("Cookie", cookie)
	resp, err = httpClient.Do(req)
	require.Nil(t, err)
	require.Equal(t, http.StatusFound, resp.StatusCode)
}

func (suite *E2ETestSuite) TestDexLogin() {
	// Port-forward the istio-ingressgateway for this test
	go func() {
		suite.T().Log("Starting port-forward...")
		err := portForward("service", "istio-system", "istio-ingressgateway", "8080", "80", suite.stopCh)
		if err != nil {
			log.Fatalf("Port-forward failed: %+v", err)
		}
	}()
	time.Sleep(2 * time.Second)
	defer func() {
		suite.T().Log("Stopping port-forward...")
		suite.stopCh <- struct{}{}
		time.Sleep(2 * time.Second)
	}()

	t := suite.T()
	httpClient := testClient

	// Get Cookie and make authenticated request
	cookie := login(t, suite.appURL, suite.username, suite.password)
	req, err := http.NewRequest(http.MethodGet, suite.appURL.String(), nil)
	require.Nil(t, err)
	req.Header.Set("Cookie", cookie)
	resp, err := httpClient.Do(req)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// login performs an OIDC login and return the session cookie
func login(t *testing.T, appURL *url.URL, username, password string) string {

	var httpClient = testClient

	// Get the App Page.
	// This should redirect to the Dex Login page.
	resp, err := httpClient.Get(appURL.String())
	require.NoError(t, err)
	require.Equal(t, http.StatusFound, resp.StatusCode)

	// Get state value
	t.Log("Getting endpoint")
	authCodeURL := appURL.ResolveReference(mustParseURL(resp.Header.Get("Location")))

	// Start OIDC Flow by hitting the authorization endpoint
	resp, err = httpClient.Get(authCodeURL.String())
	require.Nil(t, err)
	require.Equal(t, http.StatusFound, resp.StatusCode)

	// Redirected to local auth
	loginScreen := appURL.ResolveReference(mustParseURL(resp.Header.Get("Location")))
	require.Nil(t, err)
	dexReqID := loginScreen.Query().Get("req")
	require.NotEmpty(t, dexReqID)
	_, err = httpClient.Get(loginScreen.String())
	require.NoError(t, err)

	// Post login credentials
	data := url.Values{}
	data.Set("login", username)
	data.Set("password", password)
	req, err := http.NewRequest(http.MethodPost, loginScreen.String(), strings.NewReader(data.Encode()))
	require.Nil(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	resp, err = httpClient.Do(req)
	require.Nil(t, err)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)

	// Get approval screen
	approvalScreen := resp.Request.URL.ResolveReference(mustParseURL(resp.Header.Get("Location")))
	resp, err = httpClient.Get(approvalScreen.String())
	require.Nil(t, err)

	// Get Authorization Code and call the AuthService's redirect url
	oidcRedirectURL := resp.Request.URL.ResolveReference(mustParseURL(resp.Header.Get("Location")))
	resp, err = httpClient.Get(oidcRedirectURL.String())
	require.Nil(t, err)
	require.Equal(t, http.StatusFound, resp.StatusCode)

	// Get Cookie and make authenticated request
	cookie := strings.Split(resp.Header.Get("Set-Cookie"), ";")[0]
	return cookie
}

func waitForStatefulSet(
	c client.Client,
	namespace,
	name string,
	timeout time.Duration,
	period time.Duration,
) error {

	b := backoff.NewConstantBackOff(period)
	backoff.WithMaxRetries(b, uint64(timeout/period+1))
	return backoff.Retry(func() error {
		sts := &appsv1.StatefulSet{}
		err := c.Get(context.TODO(), types.NamespacedName{Namespace: namespace, Name: name}, sts)
		if err != nil {
			log.Errorf("Error getting statefulset: %+v", err)
			return backoff.Permanent(err)
		}
		if sts.Status.ObservedGeneration != sts.Generation {
			return errors.New("StatefulSet has not converged yet")
		}
		if sts.Status.UpdatedReplicas != *sts.Spec.Replicas {
			return errors.New("StatefulSet is rolling updating")
		}
		if sts.Status.ReadyReplicas != *sts.Spec.Replicas {
			return fmt.Errorf("Statefulset not ready. Got: %v, Want: %v",
				sts.Status.ReadyReplicas, sts.Spec.Replicas)
		}
		return nil
	}, b)
}

func waitForDeployment(
	c client.Client,
	namespace,
	name string,
	timeout time.Duration,
	period time.Duration,
) error {

	b := backoff.NewConstantBackOff(period)
	backoff.WithMaxRetries(b, uint64(timeout/period+1))
	return backoff.Retry(func() error {
		deploy := &appsv1.Deployment{}
		err := c.Get(context.TODO(), types.NamespacedName{Namespace: namespace, Name: name}, deploy)
		if err != nil {
			log.Errorf("Error getting deployment: %+v", err)
			return backoff.Permanent(err)
		}
		if deploy.Status.ObservedGeneration != deploy.Generation {
			return errors.New("Deployment has not converged yet")
		}
		if deploy.Status.UpdatedReplicas != *deploy.Spec.Replicas {
			return errors.New("Deployment is rolling updating")
		}
		if deploy.Status.ReadyReplicas != *deploy.Spec.Replicas {
			return fmt.Errorf("Deployment not ready. Got: %v, Want: %v",
				deploy.Status.ReadyReplicas, deploy.Spec.Replicas)
		}
		return nil
	}, b)
}

func createK3DCluster() error {
	// FIXME: Prefer creating a cluster with a random name. Else, try to remove
	// the cluster before creating it.
	cmd := exec.Command("k3d", "cluster", "create", "e2e-test-cluster", "--k3s-server-arg",
		"--no-deploy=traefik", "--no-lb", "--wait", "--timeout", "5m",
		"--update-default-kubeconfig=false")
	cmd.Stderr, cmd.Stdout = os.Stderr, os.Stdout
	err := cmd.Run()
	if err != nil {
		return err
	}

	cmd = exec.Command("k3d", "kubeconfig", "write", "e2e-test-cluster")
	err = cmd.Run()
	if err != nil {
		return err
	}

	// FIXME: Get the kubeconfig path from the output of the above command.
	kubeconfigPath := path.Join(os.Getenv("HOME"), ".k3d/kubeconfig-e2e-test-cluster.yaml")
	os.Setenv("KUBECONFIG", kubeconfigPath)

	imageName := os.Getenv("TEST_IMAGE")
	cmd = exec.Command("k3d", "image", "import", "-c", "e2e-test-cluster", imageName)
	cmd.Stderr, cmd.Stdout = os.Stderr, os.Stdout
	return cmd.Run()
}

func deleteK3DCluster() error {
	return exec.Command("k3d", "cluster", "delete", "e2e-test-cluster").Run()
}

func applyKustomizations(kustomizations []string) error {
	for _, kust := range kustomizations {
		out, err := exec.Command("kustomize", "build", kust).Output()
		if err != nil {
			log.Errorf("Error building kustomize package %s", kust)
			return err
		}

		b := backoff.NewConstantBackOff(5 * time.Second)
		backoff.WithMaxRetries(b, 5)
		err = backoff.Retry(func() error {
			kubectlApply := exec.Command("kubectl", "apply", "-f", "-")
			kubectlApply.Stdin = bytes.NewReader(out)
			kubectlApply.Stdout, kubectlApply.Stderr = os.Stdout, os.Stderr
			err := kubectlApply.Run()
			if err != nil {
				log.Warnf("Error during kubectl apply, retrying...: %+v", err)
			}
			return err
		}, b)
		if err != nil {
			return err
		}
	}
	return nil
}

func portForward(kind, namespace, name, hostPort, targetPort string, stopCh chan struct{}) error {
	cmd := exec.Command("kubectl", "port-forward", "-n", namespace,
		fmt.Sprintf("%s/%s", kind, name), fmt.Sprintf("%s:%s", hostPort, targetPort))

	processExitedCh := make(chan struct{})
	var output []byte
	var err error
	go func() {
		output, err = cmd.CombinedOutput()
		if err != nil {
			processExitedCh <- struct{}{}
		}
	}()

	select {
	case <-stopCh:
		if err := cmd.Process.Kill(); err != nil {
			return errors.Wrap(err, "failed to kill process: %+v")
		}
		return nil
	case <-processExitedCh:
		return errors.Errorf("Port-forward process exited unexpectedly, output: %s", output)
	}
}

func mustParseURL(rawURL string) *url.URL {
	url, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return url
}
