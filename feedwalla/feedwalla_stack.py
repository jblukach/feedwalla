import datetime

from aws_cdk import (
    Duration,
    RemovalPolicy,
    SecretValue,
    Stack,
    aws_dynamodb as _dynamodb,
    aws_events as _events,
    aws_events_targets as _targets,
    aws_iam as _iam,
    aws_lambda as _lambda,
    aws_logs as _logs,
    aws_s3 as _s3,
    aws_secretsmanager as _secrets,
    aws_sns as _sns,
    aws_sns_subscriptions as _subs
)

from constructs import Construct

class FeedwallaStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        account = Stack.of(self).account

        year = datetime.datetime.now().strftime('%Y')
        month = datetime.datetime.now().strftime('%m')
        day = datetime.datetime.now().strftime('%d')

    ### S3 BUCKETS ###

        bucket = _s3.Bucket.from_bucket_name(
            self, 'bucket',
            bucket_name = 'packages-use2-lukach-io'
        )

    ### SNS TOPIC ###

        topic = _sns.Topic(
            self, 'topic',
            topic_name = 'FeedwallaAlert',
            display_name = 'FeedwallaAlert'
        )

        subscription = _subs.EmailSubscription('hello@lukach.io')

        topic.add_subscription(subscription)

    ### LAMBDA LAYER ###

        requests = _lambda.LayerVersion(
            self, 'requests',
            layer_version_name = 'requests',
            description = str(year)+'-'+str(month)+'-'+str(day)+' deployment',
            code = _lambda.Code.from_bucket(
                bucket = bucket,
                key = 'requests.zip'
            ),
            compatible_architectures = [
                _lambda.Architecture.ARM_64
            ],
            compatible_runtimes = [
                _lambda.Runtime.PYTHON_3_13
            ],
            removal_policy = RemovalPolicy.DESTROY
        )

    ### SECRET MANAGER ###

        secret = _secrets.Secret(
            self, 'secret',
            secret_name = 'feedwalla',
            secret_object_value = {
                "github": SecretValue.unsafe_plain_text("<EMPTY>"),
                "token": SecretValue.unsafe_plain_text("<EMPTY>"),
                "url": SecretValue.unsafe_plain_text("<EMPTY>")
            }
        )

    ### DYNAMODB ###

        table = _dynamodb.Table(
            self, 'table',
            table_name = 'feedwalla',
            partition_key = {
                'name': 'pk',
                'type': _dynamodb.AttributeType.STRING
            },
            sort_key = {
                'name': 'sk',
                'type': _dynamodb.AttributeType.STRING
            },
            billing_mode = _dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy = RemovalPolicy.DESTROY,
            time_to_live_attribute = 'ttl',
            deletion_protection = True,
            point_in_time_recovery_specification = _dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled = True
            )
        )

    ### IAM ROLE ###

        role = _iam.Role(
            self, 'role',
            assumed_by = _iam.ServicePrincipal(
                'lambda.amazonaws.com'
            )
        )

        role.add_managed_policy(
            _iam.ManagedPolicy.from_aws_managed_policy_name(
                'service-role/AWSLambdaBasicExecutionRole'
            )
        )

        role.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    'dynamodb:PutItem',
                    'dynamodb:Query',
                    'sns:Publish'
                ],
                resources = [
                    '*'
                ]
            )
        )

        secret.grant_read(role)

    ### EXPORT LAMBDA ###

        export = _lambda.Function(
            self, 'export',
            runtime = _lambda.Runtime.PYTHON_3_13,
            architecture = _lambda.Architecture.ARM_64,
            code = _lambda.Code.from_asset('export'),
            handler = 'export.handler',
            environment = dict(
                DYNAMODB_TABLE = table.table_name,
                SECRET_MGR_ARN = secret.secret_arn
            ),
            timeout = Duration.seconds(900),
            memory_size = 512,
            role = role,
            layers = [
                requests
            ]
        )

        exportlogs = _logs.LogGroup(
            self, 'exportlogs',
            log_group_name = '/aws/lambda/'+export.function_name,
            retention = _logs.RetentionDays.ONE_WEEK,
            removal_policy = RemovalPolicy.DESTROY
        )

        exportevent = _events.Rule(
            self, 'exportevent',
            schedule = _events.Schedule.cron(
                minute = '*/5',
                hour = '*',
                month = '*',
                week_day = '*',
                year = '*'
            )
        )

        exportevent.add_target(
            _targets.LambdaFunction(export)
        )

    ### MONITOR LAMBDA ###

        monitor = _lambda.Function(
            self, 'monitor',
            runtime = _lambda.Runtime.PYTHON_3_13,
            architecture = _lambda.Architecture.ARM_64,
            code = _lambda.Code.from_asset('monitor'),
            handler = 'monitor.handler',
            environment = dict(
                SECRET_MGR_ARN = secret.secret_arn,
                SNS_TOPIC_ARN = topic.topic_arn
            ),
            timeout = Duration.seconds(900),
            memory_size = 512,
            role = role,
            layers = [
                requests
            ]
        )

        monitorlogs = _logs.LogGroup(
            self, 'monitorlogs',
            log_group_name = '/aws/lambda/'+monitor.function_name,
            retention = _logs.RetentionDays.ONE_WEEK,
            removal_policy = RemovalPolicy.DESTROY
        )

        monitorevent = _events.Rule(
            self, 'monitorevent',
            schedule = _events.Schedule.cron(
                minute = '20',
                hour = '11',
                month = '*',
                week_day = '*',
                year = '*'
            )
        )

        monitorevent.add_target(
            _targets.LambdaFunction(monitor)
        )

    ### RELEASE LAMBDA ###

        release = _lambda.Function(
            self, 'release',
            runtime = _lambda.Runtime.PYTHON_3_13,
            architecture = _lambda.Architecture.ARM_64,
            code = _lambda.Code.from_asset('release'),
            handler = 'release.handler',
            environment = dict(
                DYNAMODB_TABLE = table.table_name,
                SECRET_MGR_ARN = secret.secret_arn
            ),
            timeout = Duration.seconds(900),
            memory_size = 512,
            role = role,
            layers = [
                requests
            ]
        )

        releaselogs = _logs.LogGroup(
            self, 'releaselogs',
            log_group_name = '/aws/lambda/'+release.function_name,
            retention = _logs.RetentionDays.ONE_WEEK,
            removal_policy = RemovalPolicy.DESTROY
        )

        releaseevent = _events.Rule(
            self, 'releaseevent',
            schedule = _events.Schedule.cron(
                minute = '0',
                hour = '10',
                month = '*',
                week_day = '*',
                year = '*'
            )
        )

        releaseevent.add_target(
            _targets.LambdaFunction(release)
        )

    ### OIDC ###

        provider = _iam.OpenIdConnectProvider(
            self, 'provider',
            url = 'https://token.actions.githubusercontent.com',
            client_ids = [
                'sts.amazonaws.com'
            ]
        )

        github = _iam.Role(
            self, 'github',
            assumed_by = _iam.WebIdentityPrincipal(provider.open_id_connect_provider_arn).with_conditions(
                {
                    "StringLike": {
                        "token.actions.githubusercontent.com:sub": "repo:jblukach/feedwalla:*"
                    }
                }
            )
        )

        github.add_managed_policy(
            _iam.ManagedPolicy.from_aws_managed_policy_name(
                'ReadOnlyAccess'
            )
        )   

        github.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    'cloudformation:CreateChangeSet',
                    'cloudformation:DeleteChangeSet',
                    'cloudformation:DescribeChangeSet',
                    'cloudformation:DescribeStacks',
                    'cloudformation:ExecuteChangeSet',
                    'cloudformation:CreateStack',
                    'cloudformation:UpdateStack',
                    'cloudformation:RollbackStack',
                    'cloudformation:ContinueUpdateRollback',
                    'cloudformation:DescribeStackEvents',
                    'cloudformation:GetTemplate',
                    'cloudformation:DeleteStack',
                    'cloudformation:UpdateTerminationProtection',
                    'cloudformation:GetTemplateSummary'
                ],
                resources = [
                    '*'
                ]
            )
        )

        github.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    's3:GetObject*',
                    's3:GetBucket*',
                    's3:List*',
                    's3:Abort*',
                    's3:DeleteObject*',
                    's3:PutObject*'
                ],
                resources = [
                    '*'
                ]
            )
        )

        github.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    'kms:Decrypt',
                    'kms:DescribeKey',
                    'kms:Encrypt',
                    'kms:ReEncrypt*',
                    'kms:GenerateDataKey*'
                ],
                resources = [
                    '*'
                ],
                conditions = {
                    "StringEquals": {
                        "kms:ViaService": "s3.us-east-1.amazonaws.com"
                    }
                }
            )
        )

        github.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    'kms:Decrypt',
                    'kms:DescribeKey',
                    'kms:Encrypt',
                    'kms:ReEncrypt*',
                    'kms:GenerateDataKey*'
                ],
                resources = [
                    '*'
                ],
                conditions = {
                    "StringEquals": {
                        "kms:ViaService": "s3.us-east-2.amazonaws.com"
                    }
                }
            )
        )

        github.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    'kms:Decrypt',
                    'kms:DescribeKey',
                    'kms:Encrypt',
                    'kms:ReEncrypt*',
                    'kms:GenerateDataKey*'
                ],
                resources = [
                    '*'
                ],
                conditions = {
                    "StringEquals": {
                        "kms:ViaService": "s3.us-west-2.amazonaws.com"
                    }
                }
            )
        )

        github.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    'iam:PassRole'
                ],
                resources = [
                    'arn:aws:iam::'+str(account)+':role/cdk-lukach-cfn-exec-role-'+str(account)+'-us-east-1',
                    'arn:aws:iam::'+str(account)+':role/cdk-lukach-cfn-exec-role-'+str(account)+'-us-east-2',
                    'arn:aws:iam::'+str(account)+':role/cdk-lukach-cfn-exec-role-'+str(account)+'-us-west-2'
                ]
            )
        )

        github.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    'sts:GetCallerIdentity'
                ],
                resources = [
                    '*'
                ]
            )
        )

        github.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    'ssm:GetParameter',
                    'ssm:GetParameters'
                ],
                resources = [
                    'arn:aws:ssm:us-east-1:'+str(account)+':parameter/cdk-bootstrap/lukach/version',
                    'arn:aws:ssm:us-east-2:'+str(account)+':parameter/cdk-bootstrap/lukach/version',
                    'arn:aws:ssm:us-west-2:'+str(account)+':parameter/cdk-bootstrap/lukach/version'
                ]
            )
        )
