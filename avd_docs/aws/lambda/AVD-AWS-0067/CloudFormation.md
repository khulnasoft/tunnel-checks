
Always provide a source arn for Lambda permissions

```yaml
Resources:
  GoodExample:
    Type: AWS::Lambda::Function
    Properties:
      Code:
        S3Bucket: my-bucket
        S3Key: function.zip
      Handler: index.handler
      Role: arn:aws:iam::123456789012:role/lambda-role
      Runtime: nodejs12.x
      Timeout: 5
      TracingConfig:
        Mode: Active
      VpcConfig:
        SecurityGroupIds:
          - sg-085912345678492fb
        SubnetIds:
          - subnet-071f712345678e7c8
          - subnet-07fd123456788a036

  GoodPermission:
    Type: AWS::Lambda::Permission
    Properties:
      Action: lambda:InvokeFunction
      FunctionName: !Ref GoodExample
      Principal: s3.amazonaws.com
      SourceArn: lambda.amazonaws.com
```

