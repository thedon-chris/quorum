package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/ethereum/go-ethereum/cmd/utils"
	cli "gopkg.in/urfave/cli.v1"

	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	vaultAPI "github.com/hashicorp/vault/api"
	awsauth "github.com/hashicorp/vault/builtin/credential/aws"
)

func fetchPassword(ctx *cli.Context) (string, error) {
	if usingVaultPassword(ctx) {
		return fetchPasswordFromVault(ctx)
	}
	return fetchPasswordFromCLI(ctx)
}

func fetchPasswordFromCLI(ctx *cli.Context) (string, error) {
	accountPass := strings.TrimSpace(ctx.GlobalString(utils.VoteAccountPasswordFlag.Name))
	blockPass := strings.TrimSpace(ctx.GlobalString(utils.VoteBlockMakerAccountPasswordFlag.Name))
	if accountPass != "" {
		return accountPass, nil
	} else if blockPass != "" {
		return blockPass, nil
	} else {
		utils.Fatalf("Looked for password via fetchPasswordFromCLI, but no plaintext password arguments found.")
		// Program exits before this return, only required to quiet down compiler
		return "", nil
	}
}

func fetchPasswordFromVault(ctx *cli.Context) (string, error) {
	if usingVaultPassword(ctx) {
		// Authenticate to Vault via the AWS method
		vaultConfig := vaultAPI.DefaultConfig()
		vaultConfig.Address = ctx.GlobalString(utils.VaultAddrFlag.Name)
		vaultClient, err := vaultAPI.NewClient(vaultConfig)
		if err != nil {
			log.Fatalf("Error creating Vault client: %v", err)
			return "", err
		}
		token, err := loginAws(vaultClient)
		if err != nil {
			log.Fatalf("Error getting Vault auth token from AWS: %v", err)
			return "", err
		}
		vaultClient.SetToken(token)

		// Perform the query to retrieve the password value
		vault := vaultClient.Logical()
		fullSecretPath := "/" + ctx.GlobalString(utils.VaultPrefixFlag.Name) +
			"/" + ctx.GlobalString(utils.VaultPasswordPathFlag.Name)
		secret, err := vault.Read(fullSecretPath)
		if err != nil {
			log.Fatal(err)
			return "", err
		}

		// Extract from response & return to caller
		keyname := ctx.GlobalString(utils.VaultPasswordNameFlag.Name)
		password, present := secret.Data[keyname]
		if !present {
			utils.Fatalf("fetchPasswordFromVault found a secret at specified path, but secret did not contain specified key name.")
		}
		return password.(string), nil
	}
	utils.Fatalf("fetchPasswordFromVault called even though CLI got a password argument.")
	return "", nil
}

func usingVaultPassword(ctx *cli.Context) bool {
	passwordFlags := map[cli.StringFlag]string{
		utils.VoteAccountPasswordFlag:           strings.TrimSpace(ctx.GlobalString(utils.VoteAccountPasswordFlag.Name)),
		utils.VoteBlockMakerAccountPasswordFlag: strings.TrimSpace(ctx.GlobalString(utils.VoteBlockMakerAccountPasswordFlag.Name)),
	}
	setPassFlags := make([]string, 0)
	for flag, val := range passwordFlags {
		if val != "" {
			setPassFlags = append(setPassFlags, flag.Name)
		}
	}
	if len(setPassFlags) > 0 {
		if len(setPassFlags) == 1 {
			return false
		}
		utils.Fatalf("Too many (%v) password flags have been set.  Only one of the following should be supplied: %v", len(setPassFlags), setPassFlags)
		return false
	} else {
		vaultFlags := map[cli.StringFlag]string{
			utils.VaultAddrFlag:         strings.TrimSpace(ctx.GlobalString(utils.VaultAddrFlag.Name)),
			utils.VaultPrefixFlag:       strings.TrimSpace(ctx.GlobalString(utils.VaultPrefixFlag.Name)),
			utils.VaultPasswordNameFlag: strings.TrimSpace(ctx.GlobalString(utils.VaultPasswordNameFlag.Name)),
			utils.VaultPasswordPathFlag: strings.TrimSpace(ctx.GlobalString(utils.VaultPasswordPathFlag.Name)),
		}
		missingFlags := make([]string, 0)
		for flag, val := range vaultFlags {
			if val == "" {
				missingFlags = append(missingFlags, flag.Name)
			}
		}
		if len(missingFlags) > 0 {
			utils.Fatalf("No account password specified, but missing flags required for retrieving password from Vault.  Please supply: %v", missingFlags)
		}
		return true
	}
}

// Expects to be running in EC2
func getIAMRole() (string, error) {
	svc := ec2metadata.New(session.New())
	iam, err := svc.IAMInfo()
	if err != nil {
		return "", err
	}
	// Our instance profile conveniently has the same name as the role
	profile := iam.InstanceProfileArn
	splitArn := strings.Split(profile, "/")
	if len(splitArn) < 2 {
		return "", fmt.Errorf("No / character found in instance profile ARN")
	}
	role := splitArn[1]
	return role, nil
}

func loginAws(v *vaultAPI.Client) (string, error) {
	// Login data args are left empty so that Vault's AWSAuth implementation
	// knows to let AWS's EnvProvider handle it.  The EnvProvider searches the
	// environment for these values: https://github.com/aws/aws-sdk-go/blob/master/aws/credentials/env_provider.go
	loginData, err := awsauth.GenerateLoginData( /*accessKey=*/ "" /*secretKey=*/, "" /*sessionToken=*/, "" /*headerValue=*/, "")
	if err != nil {
		return "", err
	}
	if loginData == nil {
		return "", fmt.Errorf("Got nil response from GenerateLoginData")
	}

	role, err := getIAMRole()
	if err != nil {
		return "", err
	}
	loginData["role"] = role

	path := "auth/aws/login"

	secret, err := v.Logical().Write(path, loginData)
	if err != nil {
		return "", err
	}
	if secret == nil {
		return "", fmt.Errorf("Empty secret response from credential provider.")
	}
	if secret.Auth == nil {
		return "", fmt.Errorf("Secret contains no auth data.")
	}
	if secret.Auth.ClientToken == nil {
		return "", fmt.Errorf("Secret's auth data contains no client token.")
	}

	token := secret.Auth.ClientToken
	return token, nil
}
