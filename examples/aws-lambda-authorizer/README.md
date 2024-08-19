# JWT Block Example: AWS Lambda Authorizer

This example demonstrates using JWT Block as a Lambda authorizer.
It uses Terraform to provision an AWS environment:
- Dedicated VPC and private subnets.
- API Gateway that sends web requests to the Lambda if a custom authorizer approves.
- Lambda function with the JWT Block binary.
- Redis ElastiCache cluster for the blocklist.

The Lambda function acts as both a web API endpoint (`POST /block`)
and a [request-based](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html#api-gateway-lambda-authorizer-choose) Lambda authorizer for the API Gateway.

A Lambda authorizer takes the caller's identity as the input and returns
an IAM policy as the output. The API Gateway then evaluates the returned policy to allow or deny the request.

## Usage

Set the AWS profile to use as an environment variable and run `make`.
This will build JWT Block, deploy it to AWS via Terraform, and
provision all of the other necessary infrastructure for the example
(e.g. Redis ElastiCache).

```sh
export AWS_PROFILE=myaccount
make
```


## Resources

- [Use API Gateway Lambda authorizers](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html) (Amazon)
- [Control access to HTTP APIs with AWS Lambda authorizers](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-lambda-authorizer.html) (Amazon)