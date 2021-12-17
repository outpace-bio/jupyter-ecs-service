from typing import Dict, Tuple
import yaml
import urllib.request

from aws_cdk import (
    aws_ec2 as ec2,
    aws_ecs as ecs,
    aws_efs as efs,
    aws_iam as iam,
    aws_ecs_patterns as ecs_patterns,
    aws_cognito as cognito,
    aws_elasticloadbalancingv2 as lb,
    aws_certificatemanager as acm,
    aws_route53 as route53,
    aws_route53_targets as route53_targets,
    custom_resources as cr,
    aws_logs as logs,
    aws_kms as kms,
    core as cdk
)

from constants import BASE_NAME

#TODO - move to config file
MAX_CPU = 512
MEMORY_LIMIT = 2048
LOAD_BALANCER_PORT = 443
CONTAINER_PORT = 8000
HOST_PORT = 8000

ECS_SG_NAME = f"{BASE_NAME}ServiceSG"
ECS_SG_DESCRIPT = "Jupyter ECS service containers security group"

class Parser():

    def __init__(self, file_path: str) -> None:
        pass


class JupyterEcsServiceStack(cdk.Stack):

    def __init__(self, scope: cdk.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)


        self.__vpc = self.configure_vpc()
        efs_instance, efs_mount = self.__configure_efs()
        
       
        # General configuration variables

        config_yaml = yaml.load(
            open('config.yaml'), Loader=yaml.FullLoader)

        domain_prefix = config_yaml['domain_prefix']

        application_prefix = 'jupyter-' + domain_prefix
        suffix = f'secure'.lower()


        jupyter_lb_security_group = self.__configure_lb_sg()

        jupyter_service_security_group = self.__configue_ecs_sg(self.__vpc)

        
        self.__efs_sg = self.configure_efs_sg(self.__vpc, jupyter_service_security_group)


       
        # ECS clusters ALB, hosted zone records and certificates
        jupyter_ecs_loadbalancer = self.__configure_load_balancer(self.__vpc, jupyter_lb_security_group)
        jupyter_hosted_zone = self.__configure_hosted_zone(config_yaml)
        jupyter_route53_record = self.__configure_a_record(jupyter_hosted_zone, application_prefix, jupyter_ecs_loadbalancer)        
        jupyter_certificate = self.__configure_certificate(jupyter_hosted_zone)
        jupyter_ecs_task_definition = self.__configure_task_definition(efs_instance)


        cognito_user_pool, cognito_user_pool_domain, cognito_app_client, cognito_user_pool_client_secret = self.__configure_cognito(application_prefix, suffix, jupyter_route53_record, config_yaml)

        # ECS Container definition, service, target group and ALB attachment
        jupyter_ecs_container = self.__configure_ecs_container(jupyter_ecs_task_definition, config_yaml, cognito_app_client, jupyter_route53_record, cognito_user_pool_client_secret, cognito_user_pool_domain)
        jupyter_ecs_service = self.__configure_ecs(self.__vpc, jupyter_ecs_task_definition, jupyter_ecs_loadbalancer, config_yaml, jupyter_service_security_group)
        self.__configure_ecs_lb_listener(jupyter_ecs_loadbalancer, jupyter_certificate, jupyter_ecs_service)

        # Output the service URL to CloudFormation outputs
        cdk.CfnOutput(
            self,
            f'{BASE_NAME}JupyterHubURL',
            value='https://' + jupyter_route53_record.domain_name
        )


    def __configure_ecs_lb_listener(self, jupyter_ecs_loadbalancer, jupyter_certificate, jupyter_ecs_service) -> None:
        jupyter_ecs_loadbalancer.add_listener(
            f'{BASE_NAME}ServiceALBListener',
            protocol=lb.ApplicationProtocol.HTTPS,
            port=LOAD_BALANCER_PORT,
            certificates=[jupyter_certificate],
            default_action=lb.ListenerAction.forward(
                target_groups=[jupyter_ecs_service.target_group])
        )

    
    def __configure_ecs_container(
        self, jupyter_ecs_task_definition, config_yaml, cognito_app_client: cognito.UserPoolClient, jupyter_route53_record: route53.ARecord, cognito_user_pool_client_secret, 
        cognito_user_pool_domain: cognito.UserPoolDomain, efs_mount
    ):
        jupyter_ecs_container = jupyter_ecs_task_definition.add_container(
            f'{BASE_NAME}Container',
            image=ecs.ContainerImage.from_registry(
                config_yaml['container_image']),
            privileged=False,
            port_mappings=[
                ecs.PortMapping(
                    container_port=CONTAINER_PORT,
                    host_port=HOST_PORT,
                    protocol=ecs.Protocol.TCP
                )
            ],
            logging=ecs.LogDriver.aws_logs(
                stream_prefix=f'{BASE_NAME}ContainerLogs-',
                log_retention=logs.RetentionDays.ONE_WEEK
            ),
            environment={
                'OAUTH_CALLBACK_URL': 'https://' + jupyter_route53_record.domain_name + '/hub/oauth_callback',
                'OAUTH_CLIENT_ID': cognito_app_client.user_pool_client_id,
                'OAUTH_CLIENT_SECRET': cognito_user_pool_client_secret,
                'OAUTH_LOGIN_SERVICE_NAME': config_yaml['oauth_login_service_name'],
                'OAUTH_LOGIN_USERNAME_KEY': config_yaml['oauth_login_username_key'],
                'OAUTH_AUTHORIZE_URL': 'https://' + cognito_user_pool_domain.domain_name + '.auth.' + self.region + '.amazoncognito.com/oauth2/authorize',
                'OAUTH_TOKEN_URL': 'https://' + cognito_user_pool_domain.domain_name + '.auth.' + self.region + '.amazoncognito.com/oauth2/token',
                'OAUTH_USERDATA_URL': 'https://' + cognito_user_pool_domain.domain_name + '.auth.' + self.region + '.amazoncognito.com/oauth2/userInfo',
                'OAUTH_SCOPE': ','.join(config_yaml['oauth_scope'])
            }
        )
        
        jupyter_ecs_container.add_mount_points(efs_mount)

        return jupyter_ecs_container

    def __configure_certificate(self, hosted_zone: route53.PublicHostedZon) -> acm.Certificate:
        certificate = acm.Certificate(
            self,
            f'{BASE_NAME}Certificate',
            domain_name='*.' + hosted_zone.zone_name,
            validation=acm.CertificateValidation.from_dns(
                hosted_zone=hosted_zone)
        )
        return certificate

    def __configure_a_record(self, hosted_zone: route53.PublicHostedZone, prefix: str, ecs_lb: lb.ApplicationLoadBalancer) -> route53.ARecord:
        a_record = route53.ARecord(
            self,
            f'{BASE_NAME}LBRecord',
            zone=hosted_zone,
            record_name=prefix,
            target=route53.RecordTarget(alias_target=(
                route53_targets.LoadBalancerTarget(ecs_lb)))
        )

        return a_record

    def __configue_ecs_sg(self, vpc) -> ec2.SecurityGroup:
        ecs_sg = ec2.SecurityGroup(
            self,
            ECS_SG_NAME,
            vpc=vpc,
            description=ECS_SG_DESCRIPT,
            allow_all_outbound=True
        )
        return ecs_sg


    def __configure_lb_sg(self) -> ec2.SecurityGroup:
        load_balancer_sg = ec2.SecurityGroup(
            self,
            f'{BASE_NAME}LBSG',
            vpc=self.__vpc,
            description='Jupyter ECS service load balancer security group',
            allow_all_outbound=True
        )
        
        # Open ingress to the deploying computer public IP
        my_ip_cidr = urllib.request.urlopen(
            'http://checkip.amazonaws.com').read().decode('utf-8').strip() + '/32'

        load_balancer_sg.add_ingress_rule(
            peer=ec2.Peer.ipv4(cidr_ip=my_ip_cidr),
            connection=ec2.Port.tcp(port=443),
            description='Allow HTTPS traffic'
        )

        return load_balancer_sg

    def __configure_hosted_zone(self, config_yaml) -> route53.PublicHostedZone:
        hosted_zone = route53.PublicHostedZone.from_hosted_zone_attributes(
            self,
            f'{BASE_NAME}HostedZone',
            hosted_zone_id=config_yaml['hosted_zone_id'],
            zone_name=config_yaml['hosted_zone_name']
        )
        return hosted_zone

    def __configure_load_balancer(self, vpc, lb_sg: ec2.SecurityGroup) -> lb.ApplicationLoadBalancer:
        load_balancer = lb.ApplicationLoadBalancer(
            self,
            f'{BASE_NAME}ServiceALB',
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            internet_facing=True
        )

        load_balancer.add_security_group(
            ec2.SecurityGroup.from_security_group_id(
                self,
                f'{BASE_NAME}ImportedLBSG',
                security_group_id=lb_sg.security_group_id,
                mutable=False
            )
        )

        return load_balancer

    def generate_task_role(self) -> iam.Role:
        task_role = iam.Role(
                self,
                f'{BASE_NAME}TaskRole',
                assumed_by=iam.ServicePrincipal('ecs-tasks.amazonaws.com')
            )

        task_role.add_to_policy(
            iam.PolicyStatement(
                resources=['*'],
                actions=['cloudwatch:PutMetricData', 'cloudwatch:ListMetrics']
            )
        )

        task_role.add_to_policy(
            iam.PolicyStatement(
                resources=['*'],
                actions=[
                    'logs:CreateLogStream',
                    'logs:DescribeLogGroups',
                    'logs:DescribeLogStreams',
                    'logs:CreateLogGroup',
                    'logs:PutLogEvents',
                    'logs:PutRetentionPolicy'
                ]
            )
        )

        task_role.add_to_policy(
            iam.PolicyStatement(
                resources=['*'],
                actions=['ec2:DescribeRegions']
            )
        )

        return task_role


    def __configure_ecs(self, vpc, ecs_task_def, ecs_load_balancer, config_yaml, ecs_sg) -> ecs_patterns.ApplicationLoadBalancedFargateService:
        ecs_cluster = ecs.Cluster(
            self, f'{BASE_NAME}Cluster',
            vpc=vpc
        )

        ecs_service = ecs_patterns.ApplicationLoadBalancedFargateService(
            self, f'{BASE_NAME}Service',
            cluster=ecs_cluster,
            task_definition=ecs_task_def,
            load_balancer=ecs_load_balancer,
            desired_count=config_yaml['num_containers'],
            security_groups=[ecs_sg],
            open_listener=False
        )

        ecs_service.target_group.configure_health_check(
            path='/hub',
            enabled=True,
            healthy_http_codes='200-302'
        )

        return ecs_service

    
    def __configure_task_definition(self, efs_instance: efs.FileSystem) -> ecs.FargateTaskDefinition:
        # ECS Task definition and volumes

        task_definition = ecs.FargateTaskDefinition(
            self,
            f'{BASE_NAME}TaskDefinition',
            cpu=MAX_CPU,
            memory_limit_mib=MEMORY_LIMIT,
            execution_role=self.generate_execution_role(),
            task_role=self.generate_task_role()
        )

        task_definition.add_volume(
            name='efs-volume',
            efs_volume_configuration=ecs.EfsVolumeConfiguration(
                file_system_id=efs_instance.file_system_id
            )
        )

        return task_definition


    def generate_execution_role(self) -> iam.Role:
        # Define IAM roles and policies

        execution_role = iam.Role(
            self, f'{BASE_NAME}TaskExecutionRole',
            assumed_by=iam.ServicePrincipal('ecs-tasks.amazonaws.com')
        )

        execution_role.add_managed_policy(
            iam.ManagedPolicy.from_managed_policy_arn(
                self,
                f'{BASE_NAME}ServiceRole',
                managed_policy_arn='arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy'
            )
        )

        return execution_role


    def configure_vpc(self) -> ec2.Vpc:
        # VPC and security groups

        jupyter_vpc = ec2.Vpc(
            self, f'{BASE_NAME}Vpc',
            max_azs=2
        )

        return jupyter_vpc


    def configure_efs_sg(self, vpc, jupyter_service_security_group) -> ec2.SecurityGroup:
        efs_sg = ec2.SecurityGroup(
            self,
            f'{BASE_NAME}EFSSG',
            vpc=vpc,
            description='Jupyter shared filesystem security group',
            allow_all_outbound=True
        )

        efs_sg.connections.allow_from(
            jupyter_service_security_group,
            port_range=ec2.Port.tcp(2049),
            description='Allow NFS from ECS Service containers'
        )

        return efs_sg


    def __configure_cmk_for_efs(self) -> kms.Key:

        efs_cmk = kms.Key(
            self,
            f'{BASE_NAME}EFSCMK',
            alias='jupyter-ecs-efs-cmk',
            description='CMK for EFS Encryption',
            enabled=True,
            enable_key_rotation=True,
            trust_account_identities=True,
            removal_policy=cdk.RemovalPolicy.DESTROY
        )

        return efs_cmk


    def __configure_efs(self) -> Tuple[efs.FileSystem, ecs.MountPoint]:
        efs_cmk = self.__configure_cmk_for_efs()

        efs_instance = efs.FileSystem(
            self,
            f'{BASE_NAME}EFS',
            vpc=self.__vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE),
            security_group=self.__efs_sg,
            removal_policy=cdk.RemovalPolicy.DESTROY,
            encrypted=True,
            kms_key=efs_cmk
        )

        efs_mount = ecs.MountPoint(
            container_path='/home',
            source_volume='efs-volume',
            read_only=False
        )

        return efs_instance, efs_mount



    def __configure_cognito(
        self, app_prefix: str, app_suffix: str, a_record: route53.ARecord, config_yaml
        ) -> Tuple[cognito.UserPool, cognito.UserPoolDomain, cognito.UserPoolClient, str]:
        # User pool and user pool OAuth client

        cognito_user_pool = cognito.UserPool(
            self,
            f'{BASE_NAME}UserPool',
            removal_policy=cdk.RemovalPolicy.DESTROY
        )

        cognito_user_pool_domain = cognito.UserPoolDomain(
            self,
            f'{BASE_NAME}UserPoolDomain',
            cognito_domain=cognito.CognitoDomainOptions(
                domain_prefix=app_prefix + '-' + app_suffix),
            user_pool=cognito_user_pool
        )

        cognito_app_client = cognito.UserPoolClient(
            self,
            f'{BASE_NAME}UserPoolClient',
            user_pool=cognito_user_pool,
            generate_secret=True,
            supported_identity_providers=[
                cognito.UserPoolClientIdentityProvider.COGNITO],
            prevent_user_existence_errors=True,
            o_auth=cognito.OAuthSettings(
                callback_urls=[
                    'https://' + a_record.domain_name + '/hub/oauth_callback'],
                flows=cognito.OAuthFlows(
                    authorization_code_grant=True,
                    implicit_code_grant=True
                ),
                scopes=[cognito.OAuthScope.PROFILE, cognito.OAuthScope.OPENID]
            )
        )

        describe_cognito_user_pool_client = cr.AwsCustomResource(
            self,
            f'{BASE_NAME}UserPoolClientIDResource',
            policy=cr.AwsCustomResourcePolicy.from_sdk_calls(
                resources=cr.AwsCustomResourcePolicy.ANY_RESOURCE),
            on_create=cr.AwsSdkCall(
                service='CognitoIdentityServiceProvider',
                action='describeUserPoolClient',
                parameters={'UserPoolId': cognito_user_pool.user_pool_id,
                            'ClientId': cognito_app_client.user_pool_client_id},
                physical_resource_id=cr.PhysicalResourceId.of(
                    cognito_app_client.user_pool_client_id)
            )
        )

        cognito_user_pool_client_secret = describe_cognito_user_pool_client.get_response_field(
            'UserPoolClient.ClientSecret')

        # Cognito admin users from admins file
        with open('docker/admins') as fp:
            lines = fp.readlines()
            for line in lines:
                cr.AwsCustomResource(
                    self,
                    f'{BASE_NAME}UserPoolAdminUserResource',
                    policy=cr.AwsCustomResourcePolicy.from_sdk_calls(
                        resources=cr.AwsCustomResourcePolicy.ANY_RESOURCE
                    ),
                    on_create=cr.AwsSdkCall(
                        service='CognitoIdentityServiceProvider',
                        action='adminCreateUser',
                        parameters={
                            'UserPoolId': cognito_user_pool.user_pool_id,
                            'Username': line.strip(),
                            'TemporaryPassword': config_yaml['admin_temp_password']
                        },
                        physical_resource_id=cr.PhysicalResourceId.of(
                            cognito_user_pool.user_pool_id
                        )
                    )
                )

        return cognito_user_pool, cognito_user_pool_domain, cognito_app_client, cognito_user_pool_client_secret