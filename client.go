package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/api"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

const (
	// AUTH used in the vault REST path for login endpoint
	AUTH = "auth"

	// ClientToken the json name field of the client token we get in the login response
	ClientToken = "client_token"

	// JWT vault token header for querying the secrets
	JWT = "X-Vault-Token"

	// DATA the json field object name representing the secrets
	DATA = "data"

	// Kubernetes auth
	KubernetesAuth = "KUBERNETES"

	// App Role
	AppRoleAuth = "APP_ROLE"

	// Login Endpoint
	LoginEndpoint = "LOGIN_ENDPOINT"
)

var (
	// Info logger
	Info *log.Logger

	// Error logger
	Error *log.Logger
)

func init() {
	Info = log.New(os.Stdout,
		"INFO: ",
		log.Ldate|log.Ltime|log.Llongfile)

	Error = log.New(os.Stdout,
		"ERROR: ",
		log.Ldate|log.Ltime|log.Llongfile)
}

// AuthMethod the authentication method
type AuthMethod string

// Config for vault
type Config struct {

	// AuthMethod the authentication method
	AuthMethod AuthMethod `yaml:"auth_method"`

	// Token the vault kube token path only required fro kube auth method
	Token string `yaml:"token"`

	// Role The role attached to the JWT vault token
	Role string `yaml:"role"`

	// SecretPath a string the secret path
	SecretPath string `yaml:"secret_path"`

	// Address the vault url
	Address string `yaml:"address"`

	// TLSConfig the tls config
	TLSConfig TLSConfig `yaml:"tls_config"`

	// RoleId only required for App role auth method
	RoleId string `yaml:"role_id"`

	//SecretId only required for app role auth method
	SecretId string `yaml:"secret_id"`
}

// TLSConfig contains the parameters needed to configure TLS on the HTTP client
// used to communicate with Vault.
type TLSConfig struct {
	// CACert is the path to a PEM-encoded CA cert file to use to verify the
	// Vault server SSL certificate.
	CACert string `yaml:"ca_cert"`

	// CAPath is the path to a directory of PEM-encoded CA cert files to verify
	// the Vault server SSL certificate.
	CAPath string `yaml:"ca_path"`

	// ClientCert is the path to the certificate for Vault communication
	ClientCert string `yaml:"client_cert"`

	// ClientKey is the path to the private key for Vault communication
	ClientKey string `yaml:"client_key"`

	// TLSServerName, if set, is used to set the SNI host when connecting via
	// TLS.
	TLSServerName string `yaml:"tls_server_name"`

	// Insecure enables or disables SSL verification
	Insecure bool `yaml:"insecure"`
}

// SecretLoader used for Vault HTTP client
type SecretLoader struct {
	data   map[string]interface{}
	config Config
}

// KubeAuthBody is the body request for the vault login request
type KubeAuthBody struct {
	Role string `json:"role"`
	Jwt  string `json:"jwt, string"`
}

// AppRoleAuthBody is the body request for the vault login request
type AppRoleAuthBody struct {
	RoleID   string `json:"role_id"`
	SecretID string `json:"secret_id, string"`
}

// LoginRequest
type LoginRequest struct {
	Body     []byte
	Endpoint string
}

// NewClientWithConfig returns an instance of the SecretLoader
func NewClientWithConfig(cf Config) (SecretLoader, error) {
	// 1. Login to vault using the provided Token
	token, err := Login(cf)
	if err != nil {
		return SecretLoader{}, err
	}

	// 2. Load all the secrets
	secrets, err := loadAllSecrets(token, cf)
	if err != nil {
		return SecretLoader{}, err
	}
	if secrets == nil {
		return SecretLoader{}, errors.New("There are no secrets in the given path.")
	}
	return SecretLoader{data: secrets, config: cf}, nil
}

// NewClient returns an instance of the Secret Loader with the given configuration file
func NewClient(file string) (SecretLoader, error) {
	var config Config
	cf, err := ioutil.ReadFile(file)
	if err != nil {
		return SecretLoader{}, err
	}

	// unmarshall the config
	err = yaml.Unmarshal(cf, &config)
	if err != nil {
		return SecretLoader{}, err
	}
	return NewClientWithConfig(config)
}

// Login to the vault server using the given auth token
func Login(cf Config) (string, error) {
	loginRequest, err := buildLoginRequest(cf)
	if err != nil {
		return "", err
	}

	// Enable SSL connection
	tlsConfig := api.TLSConfig{cf.TLSConfig.CACert,
		cf.TLSConfig.CAPath,
		cf.TLSConfig.ClientCert,
		cf.TLSConfig.ClientKey,
		cf.TLSConfig.TLSServerName,
		cf.TLSConfig.Insecure}

	// vault client config
	config := api.Config{Address: cf.Address}
	config.ConfigureTLS(&tlsConfig)

	client, err := api.NewClient(&config)
	if err != nil {
		return "", err
	}
	// Attempt login
	request := client.NewRequest(http.MethodPost, loginRequest.Endpoint)
	request.Body = bytes.NewReader(loginRequest.Body)
	response, err := client.RawRequest(request)
	if err != nil {
		Error.Printf("Failed to login to vault using %s auth method", cf.AuthMethod)
		return "", err
	}
	if response.StatusCode != http.StatusOK {
		Error.Printf("Received error status %d", response.StatusCode)
		return "", errors.New(fmt.Sprintf("Received error status %d", response.StatusCode))
	}
	defer response.Body.Close()
	// read all the bytes
	jwt, err := ioutil.ReadAll(response.Body)
	if err != nil {
		Error.Println("Failed to read the login response")
		return "", err
	}
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(string(jwt)), &result); err != nil {
		Error.Println("Failed to unmarshall the login response")
		return "", err
	}
	return result[AUTH].(map[string]interface{})[ClientToken].(string), nil
}

// ReadSecret form the vault repository for given key. If the secret is not present this functions returns an empty string
func (client *SecretLoader) ReadSecret(key string) string {
	Info.Printf("Reading secret for a given key: %s", key)
	data, ok := client.data["data"].(map[string]interface{})
	if ok {
		if val := data[key]; val != nil {
			return val.(string)
		}
		return ""
	}
	if val, ok := client.data[key]; ok {
		return val.(string)
	}
	return ""
}

// For a given auth method the login endpoint is returned
func buildLoginRequest(cf Config) (LoginRequest, error) {
	switch cf.AuthMethod {
	case KubernetesAuth:
		token, err := ioutil.ReadFile(cf.Token)
		body, err := json.Marshal(KubeAuthBody{Role: cf.Role, Jwt: string(token)})
		return LoginRequest{Body: body, Endpoint: "/v1/auth/kubernetes/login"}, err
	case AppRoleAuth:
		body, err := json.Marshal(AppRoleAuthBody{SecretID: cf.SecretId, RoleID: cf.RoleId})
		return LoginRequest{Body: body, Endpoint: "/v1/auth/approle/login"}, err
	default:
		return LoginRequest{}, errors.New(
			fmt.Sprintf("Only the following auth method are supported:%s,%s", KubernetesAuth, AppRoleAuth))
	}
}

// Load all the secrets into a  Global map
func loadAllSecrets(token string, cf Config) (map[string]interface{}, error) {

	Info.Printf("Loading secrets from the path: %s", cf.SecretPath)
	client, err := api.NewClient(&api.Config{Address: cf.Address})
	client.SetToken(token)

	// Read all the secrets
	secret, err := client.Logical().Read(cf.SecretPath)
	if err != nil || secret == nil {
		Error.Printf("Failed to load the secrets from the given path: %s", cf.SecretPath)
		return nil, err
	}
	return secret.Data, nil
}
