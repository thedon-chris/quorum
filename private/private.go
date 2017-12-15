package private

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/private/constellation"
)

type PrivateTransactionManager interface {
	Send(data []byte, from string, to []string) ([]byte, error)
	Receive(data []byte) ([]byte, error)
}

var CliCfgPath = ""

func SetCliCfgPath(cliCfgPath string) {
	CliCfgPath = cliCfgPath
}

func FromCommandLineEnvironmentOrNil(name string) PrivateTransactionManager {
	cfgPath := CliCfgPath
	if cfgPath == "" {
		cfgPath = os.Getenv(name)
	}
	if cfgPath == "" {
		return nil
	}
	return constellation.MustNew(cfgPath)
}

var P = FromCommandLineEnvironmentOrNil("PRIVATE_CONFIG")

func RegeneratePrivateConfig() {
	if P == nil {
		P = FromCommandLineEnvironmentOrNil("PRIVATE_CONFIG")
	}
}

func GetPayload(digestHex string) (string, error) {
	if P == nil {
		return "", fmt.Errorf("PrivateTransactionManager is not enabled")
	}
	if len(digestHex) < 3 {
		return "", fmt.Errorf("Invalid digest hex")
	}
	if digestHex[:2] == "0x" {
		digestHex = digestHex[2:]
	}
	b, err := hex.DecodeString(digestHex)
	if err != nil {
		return "", err
	}
	if len(b) != 64 {
		return "", fmt.Errorf("Expected a Quorum digest of length 64, but got %d", len(b))
	}
	data, err := P.Receive(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("0x%x", data), nil
