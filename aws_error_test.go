package awstokens_test

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/aws/aws-sdk-go/aws/awserr"
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
			awsErr, ok := awstokens.GetAWSError(test.err)
			if !test.shouldSucceed {
				assert.False(t, ok)
				return
			}
			if !ok {
				t.Fatal("expected this to work")
			}
			assert.Equal(t, cognitoidentityprovider.ErrCodeNotAuthorizedException, awsErr.Code())
		})
	}
}

func TestIsNetworkError(t *testing.T) {
	origErr := &net.DNSError{}
	err := awserr.New("code", "message", origErr)

	table := []struct {
		name          string
		err           error
		shouldSucceed bool
	}{
		{
			name:          "aws error on top of network error",
			err:           err,
			shouldSucceed: true,
		},
		{
			name:          "wrapped aws error on top of network error",
			err:           fmt.Errorf("wrap the error: %w", err),
			shouldSucceed: true,
		},
		{
			name:          "plain network error",
			err:           origErr,
			shouldSucceed: true,
		},
		{
			name:          "wrapped network error",
			err:           fmt.Errorf("another layer: %w", origErr),
			shouldSucceed: true,
		},
		{
			name:          "nil error",
			err:           nil,
			shouldSucceed: false,
		},
		{
			name:          "not a network error",
			err:           errors.New("not an aws error"),
			shouldSucceed: false,
		},
		{
			name:          "aws error, but no underlying network error",
			err:           awserr.New("code", "message", nil),
			shouldSucceed: false,
		},
	}

	for _, test := range table {
		test := test
		t.Run(test.name, func(t *testing.T) {
			ok := awstokens.IsNetworkError(test.err)
			assert.Equal(t, test.shouldSucceed, ok)
		})
	}
}
