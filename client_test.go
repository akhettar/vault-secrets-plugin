package main

import (
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	ExpectedToken = "15cbea62-5afd-c038-72f8-320f16755cc8"
	CheckMark     = "\u2713"
	BallotX       = "\u2717"
	Token         = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjZMNUxjVG1tUFpwa0NCaUpMdTNIRnNsZUNvRmRyejFmY3ZOaGxiSUo2LUEifQ.eyJpc3MiOiJrd"
)

func TestClientVault_LoginKubeAuthMethod(t *testing.T) {

	t.Logf("Given the vault server is up and running")
	{
		loginResponse, _ := ioutil.ReadFile("data/login_response.json")
		secretResponse, _ := ioutil.ReadFile("data/secret_response.json")
		server := StubLoginAnGetSecretEndpoints(loginResponse, secretResponse)
		defer server.Close()

		t.Logf("\tWhen Sending login request to endpoint:  \"%s\"", "\\v1\\auth\\kubernetes\\login")
		{
			config := Config{AuthMethod: KubernetesAuth, Token: Token, Role: "app-role", Address: server.URL}
			token, _ := Login(config)
			if token == ExpectedToken {
				t.Logf("\t\tShould receive the expected token \"%s\" . %v", ExpectedToken, CheckMark)
			} else {
				t.Errorf("\t\tShould receive the expected token \"%s\" . %v", ExpectedToken, BallotX)
			}
		}
	}
}

func TestClientVault_LoginAppRole(t *testing.T) {

	t.Logf("Given the vault server is up and running")
	{
		loginResponse, _ := ioutil.ReadFile("data/login_response.json")
		secretResponse, _ := ioutil.ReadFile("data/secret_response.json")
		server := StubLoginAnGetSecretEndpoints(loginResponse, secretResponse)
		defer server.Close()

		t.Logf("\tWhen Sending login request to endpoint:  \"%s\"", "\\v1\\auth\\kubernetes\\login")
		{
			config := Config{AuthMethod: AppRoleAuth, RoleId: "role_id", SecretId: "secret_id", Address: server.URL}
			token, _ := Login(config)
			if token == ExpectedToken {
				t.Logf("\t\tShould receive the expected token \"%s\" . %v", ExpectedToken, CheckMark)
			} else {
				t.Errorf("\t\tShould receive the expected token \"%s\" . %v", ExpectedToken, BallotX)
			}
		}
	}
}

func TestClientVault_LoginWithUnknownAuthMethod(t *testing.T) {

	t.Logf("Given the vault server is up and running")
	{
		loginResponse, _ := ioutil.ReadFile("data/login_response.json")
		secretResponse, _ := ioutil.ReadFile("data/secret_response.json")
		server := StubLoginAnGetSecretEndpoints(loginResponse, secretResponse)
		defer server.Close()

		t.Logf("\tWhen Sending login request to endpoint:  \"%s\"", "\\v1\\auth\\kubernetes\\login")
		{
			config := Config{AuthMethod: "Dummy", RoleId: "role_id", SecretId: "secret_id", Address: server.URL}
			_, err := Login(config)
			if err.Error() == "Only the following auth method are supported:KUBERNETES,APP_ROLE" {
				t.Logf("\t\tError message should be: \"%s\" . %v", err.Error(), CheckMark)
			} else {
				t.Errorf("\t\tError message should be: \"%s\" . %v", err.Error(), BallotX)
			}
		}
	}
}

func TestClientVault_Create_Client_Invalid_response(t *testing.T) {

	t.Logf("Given the vault server is up and running")
	{
		loginResponse, _ := ioutil.ReadFile("data/invalid_login_response.json")
		secretResponse, _ := ioutil.ReadFile("data/secret_response.json")

		server := StubLoginAnGetSecretEndpoints(loginResponse, secretResponse)
		defer server.Close()

		t.Logf("\tWhen Sending login request to endpoint:  \"%s\"", "\\v1\\auth\\kubernetes\\login")
		{
			config := Config{AuthMethod: KubernetesAuth, Token: Token, Role: "app-role", Address: server.URL}
			_, err := NewClient(config)
			if err.Error() == "invalid character '}' looking for beginning of object key string" {
				t.Logf("\t\tShould receive unmarshall error \"%s\" . %v", err.Error(), CheckMark)
			} else {
				t.Errorf("\t\tShould receive unmarshall error \"%s\" . %v", err.Error(), BallotX)
			}

		}
	}
}

func TestClientVault_Failed_to_create_Client_JWT_not_present(t *testing.T) {

	t.Logf("Given the vault server is up and running")
	{
		server := StubLoginFailureWithError()
		defer server.Close()

		t.Logf("\tWhen Sending login request to endpoint:  \"%s\"", "\\v1\\auth\\kubernetes\\login")
		{
			config := Config{AuthMethod: KubernetesAuth, Role: "app-role", Address: server.URL}
			_, err := NewClient(config)

			if err != nil {
				t.Logf("\t\tCreate client fails with message  \"%s\" . %v", err.Error(), CheckMark)
			} else {
				t.Errorf("\t\tCreate client fails with message \"%s\" . %v", err.Error(), BallotX)
			}
		}
	}
}

func TestClientVault_Failed_to_create_client_no_ca_file_found(t *testing.T) {

	t.Logf("Given the vault server is up and running")
	{
		server := StubLoginFailureWithError()
		defer server.Close()

		t.Logf("\tWhen Sending login request to endpoint:  \"%s\"", "\\v1\\auth\\kubernetes\\login")
		{
			tlsCf := TLSConfig{CAPath: "data/dummy.ca"}
			config := Config{AuthMethod: KubernetesAuth, Role: "app-role", Address: server.URL, TLSConfig: tlsCf}

			_, err := NewClient(config)

			if err != nil {
				t.Logf("\t\tCreate client fails with message  \"%s\" . %v", err.Error(), CheckMark)
			} else {
				t.Errorf("\t\tCreate client fails with message \"%s\" . %v", err.Error(), BallotX)
			}
		}
	}
}

func TestClientVault_Login_Failure_With_Error(t *testing.T) {

	t.Logf("Given the vault server is up and running")
	{
		server := StubLoginFailureWithError()
		defer server.Close()

		t.Logf("\tWhen Sending login request to endpoint:  \"%s\"", "\\v1\\auth\\kubernetes\\login")
		{
			config := Config{AuthMethod: KubernetesAuth, Role: "app-role", Address: server.URL}
			_, err := NewClient(config)

			if err != nil {
				t.Logf("\t\tlogin to the vault server should have failed with the following error message: \"%s\" . %v", err.Error(), CheckMark)
			} else {
				t.Errorf("\t\tlogin to the vault server should have failed with the following error message: \"%s\" . %v", err.Error(), BallotX)
			}
		}
	}
}

func TestClientVault_Login_Failure_With_Internal_Service_Error(t *testing.T) {

	t.Logf("Given the vault server is up and running")
	{
		server := StubLoginFailureWithInternalServerError()
		defer server.Close()

		t.Logf("\tWhen Sending login request to endpoint:  \"%s\"", "\\v1\\auth\\kubernetes\\login")
		{
			config := Config{AuthMethod: KubernetesAuth, Role: "app-role", Address: server.URL}
			_, err := NewClient(config)

			if err != nil {
				t.Logf("\t\tlogin to the vault server should have failed with the following error message: \"%s\" . %v", err.Error(), CheckMark)
			} else {
				t.Errorf("\t\tlogin to the vault server should have failed with the following error message: \"%s\" . %v", err.Error(), BallotX)
			}
		}
	}
}

func TestClientVault_Load_All_Secrets_With_Internal_Service_Error(t *testing.T) {

	t.Logf("Given the vault server is up and running")
	{
		loginResponse, _ := ioutil.ReadFile("data/login_response.json")
		server := StubReadAllSecretWithInternalError(loginResponse)
		defer server.Close()

		t.Logf("\tWhen Sending load secrets to endpoint:  \"%s\"", "\\v1\\secret\\app\\app-name\\dev")
		{
			config := Config{AuthMethod: KubernetesAuth, Role: "app-role", Address: server.URL}
			_, err := NewClient(config)

			if err != nil {
				t.Logf("\t\tLoading secrets should have failed: \"%s\" . %v", err.Error(), CheckMark)
			} else {
				t.Errorf("\t\tLoading secrets should have failed: \"%s\" . %v", err.Error(), BallotX)
			}
		}
	}
}

func TestClientVault_Load_All_Secrets_With_Error(t *testing.T) {

	t.Logf("Given the vault server is up and running")
	{
		loginResponse, _ := ioutil.ReadFile("data/login_response.json")
		server := StubReadAllSecretWithError(loginResponse)
		defer server.Close()

		t.Logf("\tWhen Sending load secrets to endpoint:  \"%s\"", "\\v1\\secret\\app\\app-name\\dev")
		{
			config := Config{AuthMethod: KubernetesAuth, Role: "app-role", Address: server.URL}
			_, err := NewClient(config)

			if err != nil {
				t.Logf("\t\tLoading secrets should have failed: \"%s\" . %v", err.Error(), CheckMark)
			} else {
				t.Errorf("\t\tLoading secrets should have failed: \"%s\" . %v", err.Error(), BallotX)
			}
		}
	}
}

func TestClientVault_Load_All_Secrets_No_Secrets_Found(t *testing.T) {

	t.Logf("Given the vault server is up and running")
	{
		loginResponse, _ := ioutil.ReadFile("data/login_response.json")
		secretResponse := []byte(`{"errors":[]}`)
		server := StubLoginAnGetSecretEndpoints(loginResponse, secretResponse)
		defer server.Close()

		t.Logf("\tWhen Sending Load secrets to endpoint:  \"%s\"", "\\v1\\secret\\app\\app-name\\dev")
		{
			config := Config{AuthMethod: KubernetesAuth, Role: "app-role", Address: server.URL}
			_, err := NewClient(config)

			if err != nil {
				t.Logf("\t\tLoading secrets should have failed: \"%s\" . %v", err.Error(), CheckMark)
			} else {
				t.Errorf("\t\tLoading secrets should have failed: \"%s\" . %v", err.Error(), BallotX)
			}
		}
	}
}

func TestClientVault_Load_All_Secrets_handle_invalid_response(t *testing.T) {

	t.Logf("Given the vault server is up and running")
	{
		loginResponse, _ := ioutil.ReadFile("data/login_response.json")
		secretResponse := []byte(`{"errors":[],}`)
		server := StubLoginAnGetSecretEndpoints(loginResponse, secretResponse)
		defer server.Close()

		t.Logf("\tWhen Sending load secrets to endpoint:  \"%s\"", "\\v1\\secret\\app\\app-name\\dev")
		{
			config := Config{AuthMethod: KubernetesAuth, Role: "app-role", Address: server.URL}
			_, err := NewClient(config)

			if err != nil {
				t.Logf("\t\tLoading secrets should have failed: \"%s\" . %v", err.Error(), CheckMark)
			} else {
				t.Errorf("\t\tLoading secrets should have failed: \"%s\" . %v", err.Error(), BallotX)
			}
		}
	}
}

func TestClientVault_ReadSecret(t *testing.T) {
	t.Logf("Given the vault server is up and running")
	{
		loginResponse, _ := ioutil.ReadFile("data/login_response.json")
		secretResponse, _ := ioutil.ReadFile("data/secret_response.json")
		server := StubLoginAnGetSecretEndpoints(loginResponse, secretResponse)
		defer server.Close()

		t.Logf("\tWhen reading secret")
		{
			config := Config{AuthMethod: KubernetesAuth, Role: "app-role", Address: server.URL, SecretPath: "/secret/app/tag-service/dev"}
			client, _ := NewClient(config)
			password := client.ReadSecret("ADMIN_PASSWORD")
			uri := client.ReadSecret("MONGO_URI")
			expectedPassword := "admin"
			expectedURI := "mongodb://user:adminG@dev-cluster.mongodb.net:27017"

			if password == expectedPassword {
				t.Logf("\t\tThe ADMIN_PASSWORD secret is successfully read from vaultn \"%s\" . %v", password, CheckMark)
			} else {
				t.Errorf("\t\tThe ADMIN_PASSWORD secret is successfully read from vaultn \"%s\" . %v", password, BallotX)
			}

			if uri == expectedURI {
				t.Logf("\t\tThe MONGO_URI secret is successfully read from vaultn \"%s\" . %v", password, CheckMark)
			} else {
				t.Errorf("\t\tThe MONGO_URI secret is successfully read from vaultn \"%s\" . %v", password, BallotX)
			}
		}
	}
}

// Http server stub for success response
func StubLoginAnGetSecretEndpoints(loginResponse []byte, secretResponse []byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.RequestURI {
		case "/v1/auth/kubernetes/login":
			w.Write(loginResponse)
		case "/v1/auth/approle/login":
			w.Write(loginResponse)
		case "/v1/secret/app/tag-service/dev":
			w.Write(secretResponse)
		default:
			http.Error(w, "secret not found", http.StatusNotFound)
			w.Write([]byte(""))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
}

// Server stub for http error
func StubLoginFailureWithError() *httptest.Server {

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.RequestURI {
		case "/v1/auth/kubernetes/login":
			http.Error(w, "Failed to login to the vault server", http.StatusInternalServerError)
			panic(errors.New("failed to login to the vault server"))
		default:
			http.Error(w, "secret not found", http.StatusNotFound)
			return
		}

	}))
}

// Server stub for http error
func StubLoginFailureWithInternalServerError() *httptest.Server {

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.RequestURI {
		case "/v1/auth/kubernetes/login":
			http.Error(w, "Failed to login to the vault server", http.StatusInternalServerError)
			return
		default:
			http.Error(w, "secret not found", http.StatusNotFound)
			return
		}

	}))
}

// Server stub for http error
func StubReadAllSecretWithError(response []byte) *httptest.Server {

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.RequestURI {
		case "/v1/auth/kubernetes/login":
			w.Write(response)
		case "/v1/secret/app/tag-service/dev":
			panic(errors.New("failed to load all the secrets"))
		default:
			http.Error(w, "secret not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
}

// Server stub for http error
func StubReadAllSecretWithInternalError(response []byte) *httptest.Server {

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.RequestURI {
		case "/v1/auth/kubernetes/login":
			w.Write(response)
		case "/v1/secret/app/tag-service/dev":
			http.Error(w, "failed to read secrets", http.StatusNotFound)
			return
		default:
			http.Error(w, "secret not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
}
