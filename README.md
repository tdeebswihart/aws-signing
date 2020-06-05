# aws-signing

This is both a library and CLI designed to aid AWS request signing.

The library provides a golang developer with several abilities stemming from a `RoundTripper`.
This library provides constructs on top of the `RoundTripper` to aid other http functions.

## Library

The transport can be created with [aws-sdk-go](https://github.com/aws/aws-sdk-go) or [aws-sdk-go-v2](https://github.com/aws/aws-sdk-go-v2).
This transport can then be used with an http client.

```go
import (
	"net/http"
	
	"github.com/aws/aws-sdk-go-v2/aws/credentials"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/chronoslynx/aws-signing/signing"
)

var credsProvider aws.CredentialsProvider
// ... set credentials ...
signer := v4.NewSigner(credsProvider)
transport := signing.NewTransport(signer, "es", "us-east-1")
httpClient := &http.Client{
	Transport: transport,
}
```

## AWS Request Signing

If aws request signing is enabled, this tool uses the same chain that the aws cli uses.
This allows you to work seamlessly between aws cli tool without setting up additional configuration for access keys. 

## aws-curl

`aws-curl` is a utility that acts as a stripped-down version of curl with AWS request signing.
It can be used as a golang binary or docker image.

```
go get -u github.com/chronoslynx/aws-signing/aws-curl

aws-curl -h
Usage: aws-curl [options...] <path>
Requests http service similar to curl with AWS signing.

Options:

 -d, --data <data>            HTTP POST data
                              Specify @- for stdin.

 -H, --header                 Pass custom header(s) to server
                              Defaults:
                                Content-Type: application/json

 -X, --request <command>      Specify request command to use
                              Default: GET
```

```
docker run --entrypoint ./aws-curl bsick7/aws-signing -h
```

## aws-reverse-proxy

`aws-reverse-proxy` is a utility to provide elasticsearch access coupled with AWS request signing.

This tool is very useful to run locally when your elasticsearch instance is behind AWS IAM.
Export AWS credentials and point this utility at your elasticsearch instance.
Now, you can curl elasticsearch as if it were sitting on your local machine.

This utility can be used as a golang binary or docker image.

```
go get -u github.com/chronoslynx/aws-signing/aws-reverse-proxy

aws-reverse-proxy -h
Usage: aws-reverse-proxy [options...]
Runs a reverse proxy signing any requests upon relay to AWS services.

Options:

 -p, --port                   Reverse proxy port to listen.
                              Default: 9200

 -a, --aws                    Use AWS Request Signing
                              Default: false
                              Env Var: AWS_SIGNING

 -e, --aws-endpoint <url>     AWS Endpoint URL.
                              Default: http://localhost:9200
                              Env Var: AWS_ENDPOINT

 -s, --aws-service <service>  AWS Service.
                              Default: es
                              Env Var: AWS_SERVICE
```

```
docker run bsick7/aws-signing -h
```

## Credit

This library was inspired by [https://github.com/sha1sum/aws_signing_client](https://github.com/sha1sum/aws_signing_client).
This library uses better configuration without modifying `http.DefaultClient`.
Also, logging is not configured on a global level.
Additionally, a reverse proxy construct is added for use in trusted environments.
