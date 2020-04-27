/*
Copyright 2020 Ayache Khettar. All rights reserved.
Use of this source file is governed by MIT license
license that can be found in LICENSE file.

Package vault provides a way of loading all the secrets for
a given Go application or a service into memory. These secrets
are then available for the application to use at run time.

Two methods of authentication are supported by this library namely, Kubernetes and App role authentication.

Here is an example on how the library is used

Kubernetes authentication

	import (
		"fmt"
		"github.com/akhettar/vault-secrets-plugin"
	)
	func main() {

		// Create a client by login into vault and read all the secrets into memory
		client, err := vault.NewClient("config/config.yml")
		if err != nil {
			vault.Error.Fatalf("Failed %v", err)
		}

		// read secret - this read from memory
		pwd := client.ReadSecret("password")
		vault.Info.Printf("Password is %s", pwd)
	}


The config yml should look like this

	auth_method: KUBERNETES
	token: data/token
	role: example_role
	secret_path: secret/data/app/config
	address: http://localhost:8080
	role_id: 62022d0a-b316-30cb-8265-b37da6763012 \
	secret_id: f4a9312b-118c-8d28-fbff-5661760e8a58
	tls_config:
	  ca_cert: eyJhbGciOiJSUzI1NiIsImtpZCI6IjZMNUxjVG1tU
	  ca_path: /var/ca
	  client_cert: eyJhbGciOiJSUzI1NiIsImtpZCI6IjZMNUxjVG1tU
	  client_key: eyJhbGciOiJSUzI1NiIsImtpZCI6IjZMNUxjVG1tU
	  tls_server_name: name
	  insecure: false


Creating a client with a config

	import (
		"fmt"
		"github.com/akhettar/vault-secrets-plugin"
	)
	func main() {
		// TLS config - if tls is not enabled, this config can be ignored
		tlsConfig := vault.TLSConfig{CAPath:"<root-ca>", ClientCert:"<public-key>", ClientKey:"<private-key>"}

		// create config
		config := vault.Config{
					Address: vault_addr,
					Role: "example",
					SecretPath: "secret/data/myapp/config",
					AuthMethod: vault.KubernetesAuth,
					Token: "<kube-token>", // this can be sourced from /var/run/secrets/kubernetes.io/serviceaccount/token
					TLSConfig:tlsConfig}

		// Create a client by login into vault and read all the secrets into memory
		client, err := vault.NewClientWithConfig(config)
		if err != nil {
			vault.Error.Fatalf("Failed %v", err)
		}

		// read secret - this read from memory
		pwd := client.ReadSecret("password")
		vault.Info.Printf("Password is %s", pwd)
	}


App role authentication

	import (
	"fmt"
	"github.com/akhettar/vault-secrets-plugin"
	)
	func main() {
		// TLS config - if tls is not enabled, this config can be ignored
		tlsConfig := vault.TLSConfig{CAPath:"<root-ca>", ClientCert:"<public-key>", ClientKey:"<private-key>"}

		// create config
		config := vault.Config{
					Address: vault_addr,
					SecretPath: "secret/data/myapp/config",
					AuthMethod: vault.AppRoleAuth,
					SecretId:"056a8b44-8473-e7d1-f76b-af86144fcabe",
					RoleId:"62022d0a-b316-30cb-8265-b37da6763012",
					TLSConfig: tlsConfig}}

		// Create a client by login into vault and read all the secrets into memory
		client, err := vault.NewClientWithConfig(config)
		if err != nil {
			vault.Error.Fatalf("Failed %v", err)
		}

		// read secret - this read from memory
		pwd := client.ReadSecret("password")
		vault.Info.Printf("Password is %s", pwd)
	}

*/
package vault
