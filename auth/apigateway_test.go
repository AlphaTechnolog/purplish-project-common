package auth

import (
	"encoding/base64"
	"os"
	"testing"

	"github.com/alphatechnolog/purplish-project-common/encryption"
)

func TestGetApiGatewayAuthToken_Valid(t *testing.T) {
	authToken := "testtoken"
	b64AuthToken := base64.StdEncoding.EncodeToString([]byte(authToken))

	result := getApiGatewayAuthToken(b64AuthToken)

	if string(result) != authToken {
		t.Errorf("Expected %s, but got %s", authToken, string(result))
	}
}

func TestGetApiGatewayAuthToken_Invalid(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()

	getApiGatewayAuthToken("Invalid base64 string")
}

func TestApiGatewayScopeCheck_Success(t *testing.T) {
	key := os.Getenv("AES_ENCRYPTION_KEY")
	if key == "" {
		key = "testtesttesttest" // Provide a default key for testing
	}
	userScopes := "scope1 scope2 scope3"
	requiredUserScopes := "scope1 scope2"

	encryptedUserScopes, err := encryption.EncryptAES([]byte(key), userScopes)
	if err != nil {
		t.Fatalf("Failed to encrypt user scopes: %v", err)
	}

	b64AuthToken := base64.StdEncoding.EncodeToString([]byte(key))

	_, err = ApiGatewayScopeCheck(b64AuthToken, encryptedUserScopes, requiredUserScopes)
	if err != nil {
		t.Errorf("Expected success, but got error: %v", err)
	}
}

func TestApiGatewayScopeCheck_MissingScope(t *testing.T) {
	key := os.Getenv("AES_ENCRYPTION_KEY")
	if key == "" {
		key = "testtesttesttest" // Provide a default key for testing
	}
	userScopes := "scope1 scope2"
	requiredUserScopes := "scope1 scope2 scope3"

	encryptedUserScopes, err := encryption.EncryptAES([]byte(key), userScopes)
	if err != nil {
		t.Fatalf("Failed to encrypt user scopes: %v", err)
	}

	b64AuthToken := base64.StdEncoding.EncodeToString([]byte(key))

	_, err = ApiGatewayScopeCheck(b64AuthToken, encryptedUserScopes, requiredUserScopes)
	if err == nil {
		t.Errorf("Expected error, but got success")
	}

	if err.Error() != "user is unauthorized to perform: scope3" {
		t.Errorf("Expected specific error message, but got: %v", err)
	}
}

func TestApiGatewayScopeCheck_DecryptFail(t *testing.T) {
	b64AuthToken := base64.StdEncoding.EncodeToString([]byte("testtesttesttest"))
	encryptedUserScopes := "invalid encrypted data"
	requiredUserScopes := "scope1"

	_, err := ApiGatewayScopeCheck(b64AuthToken, encryptedUserScopes, requiredUserScopes)

	if err == nil {
		t.Errorf("Expected error, but got success")
	}
}
