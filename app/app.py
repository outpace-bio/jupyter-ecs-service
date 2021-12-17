#!/usr/bin/env python3

from aws_cdk import core as cdk
from app.service_stack import JupyterEcsStack
from app.constants import BASE_NAME


app = cdk.App()
JupyterEcsStack(app, BASE_NAME)

app.synth()
