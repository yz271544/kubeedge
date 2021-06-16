package test

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/kubeedge/kubeedge/common/constants"
	"github.com/kubeedge/kubeedge/edge/pkg/edgehub/certificate"
	"github.com/kubeedge/kubeedge/edge/pkg/edgehub/common/certutil"
	"github.com/kubeedge/kubeedge/edge/pkg/edgehub/common/http"
	"github.com/kubeedge/kubeedge/edge/pkg/edgehub/config"
	"github.com/kubeedge/kubeedge/pkg/apis/componentconfig/edgecore/v1alpha1"
	commutil "github.com/kubeedge/kubeedge/pkg/util"
	"io/ioutil"
	"k8s.io/client-go/util/cert"
	"net"
	neturl "net/url"
	"os"
	"strings"
	"testing"
)

func TestGetCACert(t *testing.T) {
	httpURL := "https://192.168.241.166:31002"
	url := httpURL + constants.DefaultCAURL
	client := http.NewHTTPClient()
	req, err := http.BuildRequest("GET", url, nil, "", "")
	if err != nil {
		t.Error(err)
	}
	res, err := http.SendRequest(req, client)
	if err != nil {
		t.Error(err)
	}
	defer res.Body.Close()

	caCert, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Error(err)
	}

	fmt.Println(string(caCert))
	cacert := caCert

	// validate the CA certificate by hashcode
	tokenParts := strings.Split("2a0e09a337a1e85dfec6f769872fcb494f333148ddac128a54a0a2922129afe0.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MjM4MjUyODl9.CsLv38PEOQ6_8LDP2SXS7073uZhDDXlwh0bPtvWtRQs", ".")
	if len(tokenParts) != 4 {
		t.Errorf("token credentials are in the wrong format")
	}

	fmt.Println("tokenParts[0]:", tokenParts[0])

	ok, hash, newHash := ValidateCACerts(cacert, tokenParts[0])
	if !ok {
		t.Errorf("failed to validate CA certificate. tokenCAhash: %s, CAhash: %s", hash, newHash)
	}

	fmt.Println("ok:", ok)
	fmt.Println("hash:", hash)
	fmt.Println("newHash:", newHash)

	// save the ca.crt to file
	ca, err := x509.ParseCertificate(cacert)
	if err != nil {
		t.Errorf("failed to parse the CA certificate, error: %v", err)
	}

	fmt.Println(ca)

	caFile := "/home/etl/iSoft/kubeedge-dev/edgecore/etc/kubeedge/ca/rootCA.crt"
	if err = certutil.WriteCert(caFile, ca); err != nil {
		t.Errorf("failed to save the CA certificate to file: %s, error: %v", caFile, err)
	}

	fmt.Println(caFile)

	// get the edge.crt
	certURL := httpURL + constants.DefaultCertURL
	caPem := pem.EncodeToMemory(&pem.Block{Bytes: cacert, Type: cert.CertificateBlockType})

	hostnameOverride, err := os.Hostname()
	if err != nil {
		fmt.Println("err:", err)
		hostnameOverride = constants.DefaultHostnameOverride
	}
	localIP, _ := commutil.GetLocalIP(hostnameOverride)

	fmt.Println("certURL:", certURL)
	fmt.Println("caPem:", string(caPem))
	fmt.Println("localIP:", localIP)

	eh := &v1alpha1.EdgeHub{
		Enable:            true,
		Heartbeat:         15,
		ProjectID:         "e632aba927ea4ac2b575ec1603d56f10",
		TLSCAFile:         constants.DefaultCAFile,
		TLSCertFile:       constants.DefaultCertFile,
		TLSPrivateKeyFile: constants.DefaultKeyFile,
		Quic: &v1alpha1.EdgeHubQUIC{
			Enable:           false,
			HandshakeTimeout: 30,
			ReadDeadline:     15,
			Server:           net.JoinHostPort(localIP, "10001"),
			WriteDeadline:    15,
		},
		WebSocket: &v1alpha1.EdgeHubWebSocket{
			Enable:           true,
			HandshakeTimeout: 30,
			ReadDeadline:     15,
			Server:           net.JoinHostPort(localIP, "10000"),
			WriteDeadline:    15,
		},
		HTTPServer: (&neturl.URL{
			Scheme: "https",
			Host:   net.JoinHostPort(localIP, "10002"),
		}).String(),
		Token:              "",
		RotateCertificates: true,
	}

	config.Config = config.Configure{
		EdgeHub:      *eh,
		WebSocketURL: strings.Join([]string{"wss:/", eh.WebSocket.Server, eh.ProjectID, "testNode", "events"}, "/"),
		NodeName:     "testNode",
	}

	cm := certificate.NewCertManager(config.Config.EdgeHub, "testNode")

	edgeToken := strings.Join(tokenParts[1:], ".")

	fmt.Println("edgeToken:", edgeToken)

	pk, edgeCert, err := cm.GetEdgeCert(certURL, caPem, tls.Certificate{}, edgeToken)
	if err != nil {
		t.Errorf("failed to get edge certificate from the cloudcore, error: %v", err)
	}

	if err == nil {
		fmt.Println(pk)
		fmt.Println(string(edgeCert))
	}
}

// ValidateCACerts validates the CA certificate by hash code
func ValidateCACerts(cacerts []byte, hash string) (bool, string, string) {
	if len(cacerts) == 0 && hash == "" {
		return true, "", ""
	}

	newHash := hashCA(cacerts)
	return hash == newHash, hash, newHash
}

func hashCA(cacerts []byte) string {
	digest := sha256.Sum256(cacerts)
	return hex.EncodeToString(digest[:])
}
