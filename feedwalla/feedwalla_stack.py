from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    aws_dynamodb as _dynamodb,
    aws_events as _events,
    aws_events_targets as _targets,
    aws_iam as _iam,
    aws_lambda as _lambda,
    aws_logs as _logs,
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
                DYNAMODB_TABLE = table.table_name,
                FIREWALLA_API = '/firewalla/api',
                FIREWALLA_WEB = '/firewalla/web'
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

        exportevent.add_target(
            _targets.LambdaFunction(export)
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
                GITHUB_API = '/github/releases'
            ),
            timeout = Duration.seconds(900),
            retry_attempts = 0,
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
                hour = '*',
                month = '*',
                week_day = '*',
                year = '*'
            )
        )

        releaseevent.add_target(
            _targets.LambdaFunction(release)
        )
