package awstokens_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/mec07/awstokens"
	"github.com/stretchr/testify/assert"
)

func TestGetAWSError(t *testing.T) {
	err := &cognitoidentityprovider.NotAuthorizedException{}

	table := []struct {
		name          string
		err           error
		shouldSucceed bool
	}{
		{
			name:          "top level error",
			err:           err,
			shouldSucceed: true,
		},
		{
			name:          "wrapped error",
			err:           fmt.Errorf("wrap the error: %w", err),
			shouldSucceed: true,
		},
		{
			name:          "double wrap the error",
			err:           fmt.Errorf("another layer: %w", fmt.Errorf("wrap the error: %w", err)),
			shouldSucceed: true,
		},
		{
			name:          "nil error",
			err:           nil,
			shouldSucceed: false,
		},
		{
			name:          "not an aws error",
			err:           errors.New("not an aws error"),
			shouldSucceed: false,
		},
	}

	for _, test := range table {
		test := test
		t.Run(test.name, func(t *testing.T) {
			fmt.Println("before err = ", test.err)
			awsErr, ok := awstokens.GetAWSError(test.err)
			if !test.shouldSucceed {
				assert.False(t, ok)
				fmt.Println("after err = ", test.err)
				return
			}
			if !ok {
				t.Fatal("expected this to work")
			}
			assert.Equal(t, cognitoidentityprovider.ErrCodeNotAuthorizedException, awsErr.Code())
			fmt.Println("after err = ", test.err)
		})
	}
}
