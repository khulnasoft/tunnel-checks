
Set the instance to not be publicly accessible

```yaml
Resources:
  GoodExample:
    Type: AWS::AutoScaling::LaunchConfiguration
    Properties:
      ImageId: ami-123456
      InstanceType: t2.small
```

