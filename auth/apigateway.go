package auth

import (
	"encoding/base64"
	"fmt"
	"slices"
	"strings"

	"github.com/alphatechnolog/purplish-project-common/encryption"
)

func getApiGatewayAuthToken(b64AuthToken string) []byte {
	contentBytes, err := base64.StdEncoding.DecodeString(b64AuthToken)
	if err != nil {
		panic("Unable to obtain api gateway auth token: " + err.Error())
	}

	return contentBytes
}

func ApiGatewayScopeCheck(b64AuthToken, encryptedUserScopes, requiredUserScopes string) (string, error) {
	userScopes, err := encryption.DecryptAES(getApiGatewayAuthToken(b64AuthToken), encryptedUserScopes)
	if err != nil {
		return "", fmt.Errorf("cannot decrypt user scopes: %w", err)
	}

	splittedScopes := strings.Split(userScopes, " ")
	splittedRequiredScopes := strings.Split(requiredUserScopes, " ")
	missingScope := func() *string {
		for _, requiredScope := range splittedRequiredScopes {
			if !slices.Contains(splittedScopes, requiredScope) {
				return &requiredScope
			}
		}
		return nil
	}()

	if missingScope != nil {
		// This should be unreachable because the api gateway should've already validated this
		// but this failing may indicate one of two things.
		// 1. Some unknown agent is possibly trying to access to the micro directly bypassing the apigateway authorization.
		// 2. API Gateway is malfunctioning and therefore passing invalid user scopes or not validated at all..
		return "", fmt.Errorf("user is unauthorized to perform: %s", *missingScope)
	}

	return userScopes, nil
}
