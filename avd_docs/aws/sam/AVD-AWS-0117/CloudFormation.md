
Enable tracing

```yaml
Resources:
  GoodStateMachine:
    Type: AWS::Serverless::StateMachine
    Properties:
      Definition:
        StartAt: MyLambdaState
        States:
          MyLambdaState:
            End: true
            Resource: arn:aws:lambda:us-east-1:123456123456:function:my-sample-lambda-app
            Type: Task
      Role: arn:aws:iam::123456123456:role/service-role/my-sample-role
      Tracing:
        Enabled: true
```

