from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    aws_events as _events,
    aws_events_targets as _targets,
    aws_iam as _iam,
    aws_lambda as _lambda,
    aws_logs as _logs,
    aws_s3 as _s3,
    aws_ssm as _ssm
)

from constructs import Construct

class FeedwallaStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

    ### LAMBDA LAYER ###

        pkgrequests = _ssm.StringParameter.from_string_parameter_arn(
            self, 'pkgrequests',
            'arn:aws:ssm:us-east-1:070176467818:parameter/pkg/requests'
        )

        requests = _lambda.LayerVersion.from_layer_version_arn(
            self, 'requests',
            layer_version_arn = pkgrequests.string_value
        )

    ### S3 BUCKETS ###

        completed = _s3.Bucket(
            self, 'completed',
            bucket_name = 'feedwallacompleted',
            encryption = _s3.BucketEncryption.S3_MANAGED,
            block_public_access = _s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy = RemovalPolicy.DESTROY,
            auto_delete_objects = True,
            enforce_ssl = True,
            versioned = False
        )

        completed.add_lifecycle_rule(
            expiration = Duration.days(1),
            noncurrent_version_expiration = Duration.days(1)
        )

        pending = _s3.Bucket(
            self, 'pending',
            bucket_name = 'feedwallapending',
            encryption = _s3.BucketEncryption.S3_MANAGED,
            block_public_access = _s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy = RemovalPolicy.DESTROY,
            auto_delete_objects = True,
            enforce_ssl = True,
            versioned = False
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
                    's3:GetObject',
                    's3:ListBucket',
                    's3:PutObject',
                    'ssm:GetParameter'
                ],
                resources = [
                    '*'
                ]
            )
        )

    ### EXPORT LAMBDA ###

        export = _lambda.Function(
            self, 'export',
            runtime = _lambda.Runtime.PYTHON_3_13,
            architecture = _lambda.Architecture.ARM_64,
            code = _lambda.Code.from_asset('export'),
            handler = 'export.handler',
            environment = dict(
                FIREWALLA_API = '/firewalla/api',
                FIREWALLA_WEB = '/firewalla/web',
                S3_COMPLETED = completed.bucket_name,
                S3_PENDING = pending.bucket_name,
                SANS_KEY = '/sans/isc/key',
                SANS_UID = '/sans/isc/uid'
            ),
            timeout = Duration.seconds(900),
            retry_attempts = 0,
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

        #exportevent.add_target(
        #    _targets.LambdaFunction(export)
        #)
