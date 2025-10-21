from dataclasses import dataclass
from troposphere import AWSHelperFn, Template, Ref, Parameter, FindInMap, GetAtt, Output
from troposphere import elasticloadbalancingv2 as elbv2
from troposphere import ec2
from troposphere import ecs
from troposphere import certificatemanager
from troposphere import route53


@dataclass
class Alb:
    subnets: list[str | AWSHelperFn]
    vpc_id: str | AWSHelperFn

    def add_resources(self, t: Template) -> Template:
        t.add_mapping(
            "AWSRegions2PrefixListID",
            {
                "ap-northeast-1": {"PrefixList": "pl-58a04531"},
                "ap-northeast-2": {"PrefixList": "pl-22a6434b"},
                # "ap-northeast-3": {},
                "ap-south-1": {"PrefixList": "pl-9aa247f3"},
                "ap-southeast-1": {"PrefixList": "pl-31a34658"},
                "ap-southeast-2": {"PrefixList": "pl-b8a742d1"},
                # "ap-southeast-3": {"PrefixList": ""},
                "ca-central-1": {"PrefixList": "pl-38a64351"},
                "eu-central-1": {"PrefixList": "pl-a3a144ca"},
                "eu-north-1": {"PrefixList": "pl-fab65393"},
                "eu-west-1": {"PrefixList": "pl-4fa04526"},
                "eu-west-2": {"PrefixList": "pl-93a247fa"},
                "eu-west-3": {"PrefixList": "pl-75b1541c"},
                "sa-east-1": {"PrefixList": "pl-5da64334"},
                "us-east-1": {"PrefixList": "pl-3b927c52"},
                "us-east-2": {"PrefixList": "pl-b6a144df"},
                "us-west-1": {"PrefixList": "pl-4ea04527"},
                "us-west-2": {"PrefixList": "pl-82a045eb"},
            },
        )
        alb_access_log_bucket_param = t.add_parameter(
            Parameter(
                "AlbAccessLogsBucket",
                Description="S3 bucket for ALB access logs",
                Type="String",
            )
        )
        alb_domain_name_param = t.add_parameter(
            Parameter("AlbDomainName", Type="String", Description="ALB domain name")
        )
        hosted_zone_id_param = t.add_parameter(
            Parameter(
                "HostedZoneId",
                Type="String",
                Description="Route53 Hosted Zone ID for the domain",
            )
        )

        alb_cert = t.add_resource(
            certificatemanager.Certificate(
                "AlbCertificate",
                DomainName=Ref(alb_domain_name_param),
                ValidationMethod="DNS",
                DomainValidationOptions=[
                    certificatemanager.DomainValidationOption(
                        DomainName=Ref(alb_domain_name_param),
                        HostedZoneId=Ref(hosted_zone_id_param),
                    )
                ],
            )
        )

        alb_sg = t.add_resource(
            ec2.SecurityGroup(
                "AlbSecurityGroup",
                GroupDescription="Security group for ALB",
                VpcId=self.vpc_id,
                SecurityGroupEgress=[
                    ec2.SecurityGroupRule(
                        IpProtocol="-1",
                        CidrIp="127.0.0.1/32",
                        Description="Only allow egress to localhost (and prevent create of the default allow-all egress rule)",
                    )
                ],
            )
        )
        self.alb_security_group = alb_sg

        alb = t.add_resource(
            elbv2.LoadBalancer(
                "Alb",
                Subnets=self.subnets,
                SecurityGroups=[Ref(alb_sg)],
                Scheme="internet-facing",
                Type="application",
                IpAddressType="ipv4",
                LoadBalancerAttributes=[
                    elbv2.LoadBalancerAttributes(
                        Key="access_logs.s3.enabled", Value="true"
                    ),
                    elbv2.LoadBalancerAttributes(
                        Key="access_logs.s3.bucket",
                        Value=Ref(alb_access_log_bucket_param),
                    ),
                    elbv2.LoadBalancerAttributes(
                        Key="routing.http.drop_invalid_header_fields.enabled",
                        Value="true",
                    ),
                    elbv2.LoadBalancerAttributes(
                        Key="routing.http.preserve_host_header.enabled", Value="false"
                    ),
                    elbv2.LoadBalancerAttributes(
                        Key="routing.http2.enabled", Value="true"
                    ),
                ],
            )
        )

        t.add_resource(
            elbv2.Listener(
                "EnforceHttpsListener",
                Metadata={
                    "cfn_nag": {
                        "rules_to_suppress": [
                            {"id": "W56", "reason": "Redirecting to HTTPS"}
                        ]
                    }
                },
                DefaultActions=[
                    elbv2.Action(
                        Type="redirect",
                        RedirectConfig=elbv2.RedirectConfig(
                            Host="#{host}",
                            Path="/#{path}",
                            Port="443",
                            Protocol="HTTPS",
                            Query="#{query}",
                            StatusCode="HTTP_301",
                        ),
                    )
                ],
                LoadBalancerArn=Ref(alb),
                Port=80,
                Protocol="HTTP",
            )
        )
        https_listener = t.add_resource(
            elbv2.Listener(
                "HttpsListener",
                DefaultActions=[
                    elbv2.Action(
                        Type="fixed-response",
                        FixedResponseConfig=elbv2.FixedResponseConfig(
                            StatusCode="403",
                            ContentType="text/plain",
                            MessageBody="Access denied",
                        ),
                    )
                ],
                LoadBalancerArn=Ref(alb),
                Port=443,
                Protocol="HTTPS",
                Certificates=[elbv2.Certificate(CertificateArn=Ref(alb_cert))],
                SslPolicy="ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
            )
        )
        self.target_group = t.add_resource(
            elbv2.TargetGroup(
                "WebAppTargetGroup",
                HealthCheckEnabled=True,
                HealthCheckIntervalSeconds=15,
                HealthCheckPath="/ping/",
                HealthCheckPort="8000",
                HealthCheckProtocol="HTTP",
                HealthCheckTimeoutSeconds=12,
                HealthyThresholdCount=2,
                Matcher=elbv2.Matcher(HttpCode="200"),
                UnhealthyThresholdCount=2,
                Port=8000,
                Protocol="HTTP",
                ProtocolVersion="HTTP1",
                TargetType="ip",
                TargetGroupAttributes=[
                    elbv2.TargetGroupAttribute(
                        Key="deregistration_delay.timeout_seconds", Value="10"
                    ),
                    elbv2.TargetGroupAttribute(
                        Key="slow_start.duration_seconds", Value="0"
                    ),
                    elbv2.TargetGroupAttribute(Key="stickiness.enabled", Value="false"),
                    elbv2.TargetGroupAttribute(
                        Key="load_balancing.algorithm.type", Value="round_robin"
                    ),
                ],
                VpcId=self.vpc_id,
            )
        )
        t.add_resource(
            elbv2.ListenerRule(
                "AppForwardRule",
                Priority=1,
                ListenerArn=Ref(https_listener),
                Actions=[
                    elbv2.ListenerRuleAction(
                        Order=1,
                        TargetGroupArn=Ref(self.target_group),
                        Type="forward",
                    )
                ],
                Conditions=[
                    elbv2.Condition(
                        Field="host-header",
                        Values=[
                            Ref(alb_domain_name_param),
                        ],
                    )
                ],
            )
        )

        t.add_resource(
            ec2.SecurityGroupIngress(
                "CloudfrontToAlb",
                Description="Allow CloudFront access to ALB",
                GroupId=Ref(alb_sg),
                IpProtocol="tcp",
                FromPort=443,
                ToPort=443,
                SourcePrefixListId=FindInMap(
                    "AWSRegions2PrefixListID", Ref("AWS::Region"), "PrefixList"
                ),
            )
        )

        record_sets = [
            route53.RecordSet(
                Name=Ref(alb_domain_name_param),
                Type=type_,
                AliasTarget=route53.AliasTarget(
                    HostedZoneId=GetAtt(alb, "CanonicalHostedZoneID"),
                    DNSName=GetAtt(alb, "DNSName"),
                    EvaluateTargetHealth=False,
                ),
            )
            for type_ in ["A", "AAAA"]
        ]

        t.add_resource(
            route53.RecordSetGroup(
                "AlbRecordSet",
                HostedZoneId=Ref(hosted_zone_id_param),
                RecordSets=record_sets,
            )
        )

        return t


@dataclass
class EcsCluster:
    vpc_id: str | AWSHelperFn
    db_security_group_id: str | AWSHelperFn
    fs_security_group_id: str | AWSHelperFn
    alb_security_group_id: str | AWSHelperFn
    vpc_endpoints_security_group_id: str | AWSHelperFn

    def add_resources(self, t: Template) -> Template:
        self.ecs_cluster = t.add_resource(
            ecs.Cluster(
                "EcsCluster",
                CapacityProviders=["FARGATE", "FARGATE_SPOT"],
                DefaultCapacityProviderStrategy=[
                    ecs.CapacityProviderStrategyItem(
                        CapacityProvider="FARGATE", Weight=1
                    ),
                    ecs.CapacityProviderStrategyItem(
                        CapacityProvider="FARGATE_SPOT", Weight=1
                    ),
                ],
                Configuration=ecs.ClusterConfiguration(
                    ExecuteCommandConfiguration=ecs.ExecuteCommandConfiguration(
                        Logging="DEFAULT"
                    )
                ),
                ClusterSettings=[
                    ecs.ClusterSetting(Name="containerInsights", Value="enabled")
                ],
            )
        )

        web_app_sg = t.add_resource(
            ec2.SecurityGroup(
                "WebAppSG",
                GroupDescription="Security group for web application",
                VpcId=self.vpc_id,
            )
        )
        self.web_app_sg = web_app_sg
        t.add_resource(
            ec2.SecurityGroupIngress(
                "AlbToWebAppHttpIngress",
                Description="Allow ALB access to web app",
                GroupId=Ref(web_app_sg),
                IpProtocol="tcp",
                FromPort=8000,
                ToPort=8000,
                SourceSecurityGroupId=self.alb_security_group_id,
            )
        )
        t.add_resource(
            ec2.SecurityGroupEgress(
                "WebAppToVpcEndpointsEgress",
                Description="Allow web app access to VPC Endpoints",
                GroupId=Ref(web_app_sg),
                IpProtocol="tcp",
                FromPort=443,
                ToPort=443,
                DestinationSecurityGroupId=self.vpc_endpoints_security_group_id,
            )
        )
        t.add_resource(
            ec2.SecurityGroupEgress(
                "WebAppToDbEgress",
                Description="Allow web app access to DB",
                GroupId=Ref(web_app_sg),
                IpProtocol="tcp",
                FromPort=3306,
                ToPort=3306,
                DestinationSecurityGroupId=self.db_security_group_id,
            )
        )
        t.add_mapping(
            "AWSRegions2S3PrefixListID",
            {
                "ap-south-1": {"PrefixList": "pl-78a54011"},
                "eu-north-1": {"PrefixList": "pl-c3aa4faa"},
                "eu-west-3": {"PrefixList": "pl-23ad484a"},
                "eu-west-2": {"PrefixList": "pl-7ca54015"},
                "eu-west-1": {"PrefixList": "pl-6da54004"},
                "ap-northeast-3": {"PrefixList": "pl-a4a540cd"},
                "ap-northeast-2": {"PrefixList": "pl-78a54011"},
                "ap-northeast-1": {"PrefixList": "pl-61a54008"},
                "ca-central-1": {"PrefixList": "pl-7da54014"},
                "sa-east-1": {"PrefixList": "pl-6aa54003"},
                "ap-southeast-1": {"PrefixList": "pl-6fa54006"},
                "ap-southeast-2": {"PrefixList": "pl-6ca54005"},
                "eu-central-1": {"PrefixList": "pl-6ea54007"},
                "us-east-1": {"PrefixList": "pl-63a5400a"},
                "us-east-2": {"PrefixList": "pl-7ba54012"},
                "us-west-1": {"PrefixList": "pl-6ba54002"},
                "us-west-2": {"PrefixList": "pl-68a54001"},
            },
        )
        t.add_resource(
            ec2.SecurityGroupEgress(
                "WebAppToS3GatewayEndpoint",
                Description="Allow web app access to S3 via VPC Gateway Endpoint",
                GroupId=Ref(web_app_sg),
                IpProtocol="tcp",
                FromPort=443,
                ToPort=443,
                DestinationPrefixListId=FindInMap(
                    "AWSRegions2S3PrefixListID", Ref("AWS::Region"), "PrefixList"
                ),
            )
        )
        t.add_resource(
            ec2.SecurityGroupIngress(
                "WebAppToDbIngress",
                Description="Allow web app access to DB",
                GroupId=self.db_security_group_id,
                IpProtocol="tcp",
                FromPort=3306,
                ToPort=3306,
                SourceSecurityGroupId=Ref(web_app_sg),
            )
        )
        t.add_resource(
            ec2.SecurityGroupEgress(
                "AlbToWebAppEgress",
                Description="Allow ALB access to web app",
                GroupId=self.alb_security_group_id,
                IpProtocol="tcp",
                FromPort=8000,
                ToPort=8000,
                DestinationSecurityGroupId=Ref(web_app_sg),
            )
        )
        t.add_resource(
            ec2.SecurityGroupIngress(
                "WebAppToEfsIngress",
                Description="Allow web app access to EFS",
                GroupId=self.fs_security_group_id,
                IpProtocol="tcp",
                FromPort=2049,
                ToPort=2049,
                SourceSecurityGroupId=Ref(web_app_sg),
            )
        )
        t.add_resource(
            ec2.SecurityGroupEgress(
                "WebAppToEfsEgress",
                Description="Allow web app access to EFS",
                GroupId=Ref(web_app_sg),
                IpProtocol="tcp",
                FromPort=2049,
                ToPort=2049,
                DestinationSecurityGroupId=self.fs_security_group_id,
            )
        )
        return t


def main():
    t = Template()
    t.set_description("ECS-based application stack")

    vpc_id_param = t.add_parameter(
        Parameter(
            "VpcId",
            Type="String",
            Description="VPC ID where resources will be deployed",
        )
    )
    subnet_id_1_param = t.add_parameter(
        Parameter("SubnetId1", Type="String", Description="Subnet ID 1")
    )
    subnet_id_2_param = t.add_parameter(
        Parameter("SubnetId2", Type="String", Description="Subnet ID 2")
    )
    db_security_group_id_param = t.add_parameter(
        Parameter(
            "DbSecurityGroupId",
            Type="String",
            Description="Security group ID for the RDS database",
        )
    )
    fs_security_group_id_param = t.add_parameter(
        Parameter(
            "FileSystemSecurityGroupId",
            Type="String",
            Description="Security group ID for the EFS file system",
        )
    )
    vpc_endpoints_security_group_id_param = t.add_parameter(
        Parameter(
            "VpcEndpointsSecurityGroupId",
            Type="String",
            Description="Security group ID for the VPC endpoint",
        )
    )

    alb = Alb(
        vpc_id=Ref(vpc_id_param),
        subnets=[Ref(subnet_id_1_param), Ref(subnet_id_2_param)],
    )
    alb.add_resources(t)
    ecs_cluster = EcsCluster(
        vpc_id=Ref(vpc_id_param),
        db_security_group_id=Ref(db_security_group_id_param),
        fs_security_group_id=Ref(fs_security_group_id_param),
        alb_security_group_id=Ref(alb.alb_security_group),
        vpc_endpoints_security_group_id=Ref(vpc_endpoints_security_group_id_param),
    )
    ecs_cluster.add_resources(t)

    t.add_output(Output("EcsCluster", Value=Ref(ecs_cluster.ecs_cluster)))
    t.add_output(Output("TargetGroupArn", Value=Ref(alb.target_group)))
    t.add_output(Output("WebAppSecurityGroupId", Value=Ref(ecs_cluster.web_app_sg)))

    print(t.to_yaml())


if __name__ == "__main__":
    main()
