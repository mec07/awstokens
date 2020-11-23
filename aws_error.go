package awstokens

import (
	"errors"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/mec07/neterror"
)

// GetAWSError recursively checks if the error is an awserr.Error. It unwraps
// until it gets to the end of the error chain. A common error to look out for
// is cognitoidentityprovider.NotAuthorizedError. This is what you will be
// getting back if the refresh token has expired. For example:
//     var expired bool
//     if aerr, ok := awstokens.GetAWSError(err); ok {
//     	if aerr.Code() == cognitoidentityprovider.ErrCodeNotAuthorizedException {
//     		expired = true
//     	}
//     }
func GetAWSError(err error) (awserr.Error, bool) {
	var (
		awsErr awserr.Error
		ok     bool
	)

	for {
		if err == nil {
			break
		}

		awsErr, ok = err.(awserr.Error)
		if ok {
			break
		}

		err = errors.Unwrap(err)
	}

	return awsErr, ok
}

// IsNetworkError checks if a network error has occurred. The reason we can't
// just use `neterror.GetNetError` is because AWS errors keep the original error
// in a field instead of wrapping errors, so we have to the original error field
// too.
func IsNetworkError(err error) bool {
	// We may get a non-AWS error
	_, ok := neterror.GetNetError(err)
	if ok {
		return true
	}

	// Or we may get an awserr.Error, from which we have to extract the
	// original error
	awsErr, ok := GetAWSError(err)
	if !ok {
		return false
	}

	_, ok = neterror.GetNetError(awsErr.OrigErr())
	return ok
}
