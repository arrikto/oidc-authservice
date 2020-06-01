// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/types"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	controllerruntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"strconv"
	"strings"
	"testing"
	"time"
)

type E2ETestSuite struct {
	suite.Suite
	kubeclient client.Client
	appURL     *url.URL
	username   string
	password   string
	stopCh     chan struct{}
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

	go portForward("service", "istio-system", "istio-ingressgateway", "8080", "80", suite.stopCh)
	time.Sleep(5 * time.Second)

	suite.appURL = mustParseURL("http://127.0.0.1:8080/")
	suite.username = "user"
	suite.password = "12341234"

}

func (suite *E2ETestSuite) TearDownSuite() {
	suite.stopCh <- struct{}{}
	suite.Require().Nil(deleteK3DCluster())
}

func (suite *E2ETestSuite) TestDexLogin() {
	t := suite.T()
	client := &http.Client{
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

	appURL := suite.appURL

	// Get the App Page.
	// This should redirect to the Dex Login page.
	resp, err := client.Get(appURL.String())
	require.Nil(t, err)
	require.Equal(t, http.StatusFound, resp.StatusCode)

	// Get state value
	t.Log("Getting endpoint")
	authCodeURL := appURL.ResolveReference(mustParseURL(resp.Header.Get("Location")))

	// Start OIDC Flow by hitting the authorization endpoint
	resp, err = client.Get(authCodeURL.String())
	require.Nil(t, err)
	require.Equal(t, http.StatusFound, resp.StatusCode)

	// Redirected to local auth
	loginScreen := appURL.ResolveReference(mustParseURL(resp.Header.Get("Location")))
	require.Nil(t, err)
	dexReqID := loginScreen.Query().Get("req")
	require.NotEmpty(t, dexReqID)

	// Post login credentials
	data := url.Values{}
	data.Set("login", suite.username)
	data.Set("password", suite.password)
	req, err := http.NewRequest(http.MethodPost, loginScreen.String(), strings.NewReader(data.Encode()))
	require.Nil(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	resp, err = client.Do(req)
	require.Nil(t, err)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)

	// Get approval screen
	approvalScreen := resp.Request.URL.ResolveReference(mustParseURL(resp.Header.Get("Location")))
	resp, err = client.Get(approvalScreen.String())
	require.Nil(t, err)

	// Get Authorization Code and call the AuthService's redirect url
	oidcRedirectURL := resp.Request.URL.ResolveReference(mustParseURL(resp.Header.Get("Location")))
	resp, err = client.Get(oidcRedirectURL.String())
	require.Nil(t, err)
	require.Equal(t, http.StatusFound, resp.StatusCode)

	// Get Cookie and make authenticated request
	cookie := resp.Header.Get("Set-Cookie")
	req, err = http.NewRequest(http.MethodGet, appURL.String(), nil)
	require.Nil(t, err)
	req.Header.Set("Cookie", cookie)
	resp, err = client.Do(req)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
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
		if deploy.Status.ReadyReplicas != *deploy.Spec.Replicas {
			return fmt.Errorf("Deployment not ready. Got: %v, Want: %v",
				deploy.Status.ReadyReplicas, deploy.Spec.Replicas)
		}
		return nil
	}, b)
}

func createK3DCluster() error {
	cmd := exec.Command("k3d", "create", "cluster", "e2e-test-cluster", "--k3s-server-arg",
		"--no-deploy=traefik", "--no-lb", "--wait", "--timeout", "5m")
	cmd.Stderr, cmd.Stdout = os.Stderr, os.Stdout
	err := cmd.Run()
	if err != nil {
		return err
	}
	return exec.Command("k3d", "get", "kubeconfig", "e2e-test-cluster", "--switch").Run()
}

func deleteK3DCluster() error {
	return exec.Command("k3d", "delete", "cluster", "e2e-test-cluster").Run()
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

func portForward(kind, namespace, name, hostPort, targetPort string, stopCh chan struct{}) {
	cmd := exec.Command("kubectl", "port-forward", "-n", namespace,
		fmt.Sprintf("%s/%s", kind, name), fmt.Sprintf("%s:%s", hostPort, targetPort))
	err := cmd.Start()
	if err != nil {
		log.Errorf("Error during port-forward: %+v", err)
		os.Exit(1)
	}
	processExitedCh := make(chan struct{})
	go func() {
		err := cmd.Wait()
		if err != nil {
			log.Errorf("Port-forward exited with error: %+v", err)
		}
		processExitedCh <- struct{}{}
	}()
	select {
	case <-stopCh:
		return
	case <-processExitedCh:
		os.Exit(1)
	}

}

func mustParseURL(rawURL string) *url.URL {
	url, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return url
}
