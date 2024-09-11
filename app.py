#!/usr/bin/env python3
import os

import aws_cdk as cdk

from feedwalla.feedwalla_stack import FeedwallaStack

app = cdk.App()

FeedwallaStack(
    app, "FeedwallaStack",
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = 'us-east-1'
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = '4n6ir'
    )
)

cdk.Tags.of(app).add('Alias','lukach.io')
cdk.Tags.of(app).add('GitHub','https://github.com/jblukach/feedwalla')

app.synth()