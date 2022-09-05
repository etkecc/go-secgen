package secgen

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"

	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ssh"
)

// Keypair generates ed25519 keypair for ssh (public key, private key)
func Keypair() (string, string, error) {
	publicBytes, privateBytes, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", "", err
	}
	publicStruct, err := ssh.NewPublicKey(publicBytes)
	if err != nil {
		return "", "", err
	}

	pemblock := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: edkey.MarshalED25519PrivateKey(privateBytes),
	}
	private := pem.EncodeToMemory(pemblock)
	public := ssh.MarshalAuthorizedKey(publicStruct)

	return string(public), string(private), nil
}

// DKIM generates DKIM signature and private key (TXT record, private key)
func DKIM() (string, string, error) {
	publicBytes, privateBytes, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", "", err
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(privateBytes)
	if err != nil {
		return "", "", err
	}

	pemblock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8,
	}
	private := pem.EncodeToMemory(pemblock)
	dkim := []string{
		"v=DKIM1",
		"k=ed25519",
		"p=" + base64.StdEncoding.EncodeToString(publicBytes),
	}

	return strings.Join(dkim, "; "), string(private), nil
}
