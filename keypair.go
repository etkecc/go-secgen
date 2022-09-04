package secgen

import (
	"crypto/ed25519"
	"encoding/pem"

	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ssh"
)

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
