package awstokens

import (
	"errors"

	"github.com/aws/aws-sdk-go/aws/awserr"
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
