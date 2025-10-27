from dataclasses import dataclass, field
from troposphere import (
    AWSHelperFn,
    Equals,
    GetAZs,
    GetAtt,
    Output,
    Select,
    Sub,
    Tag,
    Template,
    Ref,
    Parameter,
)
from troposphere import ec2
from troposphere import route53resolver


@dataclass
class Nacl:
    scope: str
    vpc_id: str | Ref
    allow_ingress_from: list[tuple[str | Ref, str | AWSHelperFn]]
    allow_egress_to: list[tuple[str | Ref, str | AWSHelperFn]]
    subnets: list[ec2.Subnet]
    nacl: ec2.NetworkAcl | None = field(init=False, default=None)

    def add_resources(self, template: Template):
        self.nacl = template.add_resource(
            ec2.NetworkAcl(
                f"{self.scope}NACL",
                VpcId=self.vpc_id,
            )
        )
        template.add_resource(
            ec2.NetworkAclEntry(
                f"{self.scope}NACLDenyRDP",
                Metadata={
                    "cfn_nag": {
                        "rules_to_suppress": [
                            {
                                "id": "W72",
                                "reason": "Overlap is deliberate to explicitly deny RDP via rule with higher precedence",
                            }
                        ]
                    }
                },
                NetworkAclId=Ref(self.nacl),
                RuleNumber=90,
                Protocol=6,
                RuleAction="deny",
                Egress=False,
                CidrBlock="0.0.0.0/0",
                PortRange=ec2.PortRange(From=3389, To=3389),
            )
        )
        for i, (port, source) in enumerate(self.allow_ingress_from):
            if isinstance(port, str) and "-" in port:
                from_port = port.split("-")[0]
                to_port = port.split("-")[1]
            else:
                from_port = port
                to_port = port
            template.add_resource(
                ec2.NetworkAclEntry(
                    f"{self.scope}NACLIngress{i}",
                    NetworkAclId=Ref(self.nacl),
                    RuleNumber=100 + i,
                    Protocol=6,
                    RuleAction="allow",
                    Egress=False,
                    CidrBlock=source,
                    PortRange=ec2.PortRange(From=from_port, To=to_port),
                )
            )
        for i, (port, destination) in enumerate(self.allow_egress_to):
            if isinstance(port, str) and "-" in port:
                from_port = port.split("-")[0]
                to_port = port.split("-")[1]
            else:
                from_port = port
                to_port = port
            template.add_resource(
                ec2.NetworkAclEntry(
                    f"{self.scope}NACLEgress{i}",
                    NetworkAclId=Ref(self.nacl),
                    RuleNumber=100 + i,
                    Protocol=6,
                    RuleAction="allow",
                    Egress=True,
                    CidrBlock=destination,
                    PortRange=ec2.PortRange(From=from_port, To=to_port),
                )
            )
        for i, s in enumerate(self.subnets):
            template.add_resource(
                ec2.SubnetNetworkAclAssociation(
                    f"{self.scope}{i + 1}NACLAssoc{i}",
                    SubnetId=Ref(s),
                    NetworkAclId=Ref(self.nacl),
                )
            )


@dataclass
class Subnet:
    scope: str
    vpc: Ref
    az_index: int
    cidr_block: str
    name: str
    subnet: ec2.Subnet | None = field(init=False, default=None)

    def add_resources(self, template: Template):
        self.subnet = template.add_resource(
            ec2.Subnet(
                f"{self.scope}{self.az_index + 1}",
                VpcId=self.vpc,
                CidrBlock=self.cidr_block,
                AvailabilityZone=Select(
                    self.az_index, GetAZs(region=Ref("AWS::Region"))
                ),
                AssignIpv6AddressOnCreation=False,
                EnableDns64=False,
                Ipv6Native=False,
                MapPublicIpOnLaunch=False,
                PrivateDnsNameOptionsOnLaunch=ec2.PrivateDnsNameOptionsOnLaunch(
                    HostnameType="ip-name"
                ),
                Tags=[
                    Tag(
                        "Name",
                        Sub(f"${{AWS::StackName}}-{self.name}{self.az_index + 1}"),
                    )
                ],
            )
        )


@dataclass
class FlowLogs:
    scope: str
    vpc: Ref
    flow_logs_bucket: Ref

    def add_resources(self, template: Template):
        template.add_resource(
            ec2.FlowLog(
                f"{self.scope}FlowLogs",
                ResourceId=self.vpc,
                ResourceType="VPC",
                LogDestinationType="s3",
                LogDestination=self.flow_logs_bucket,
                TrafficType="ALL",
            )
        )


@dataclass
class Vpc:
    scope: str = ""
    num_azs: int = 2

    def add_resources(self, template: Template):
        resolver_query_log_config_param = template.add_parameter(
            Parameter(
                "ResolverQueryLogConfigId",
                Type="String",
                Description="The Route53 Resolver Query Log Config ID",
            )
        )
        flow_logs_bucket_param = template.add_parameter(
            Parameter(
                "FlowLogsBucket",
                Description="The bucket for the flow logs",
                Type="String",
            )
        )
        data_port_param = template.add_parameter(
            Parameter(
                "DataPort",
                Description="The port for the data subnet (e.g. 3306 for MySQL)",
                Type="Number",
                Default=3306,
            )
        )
        use_nat_param = template.add_parameter(
            Parameter(
                "NatGatewayRequired",
                Description="Whether to deploy NAT gateways",
                Type="String",
                AllowedValues=["true", "false"],
                Default="false",
            )
        )

        use_nat_condition = template.add_condition(
            "DeployNatGateway", Equals(Ref(use_nat_param), "true")
        )

        vpc = template.add_resource(
            ec2.VPC(
                f"{self.scope}VPC",
                CidrBlock="10.0.0.0/16",
                EnableDnsSupport=True,
                EnableDnsHostnames=True,
                Tags=[Tag("Name", Sub("${AWS::StackName}-vpc"))],
            )
        )
        self.vpc = vpc

        template.add_resource(
            route53resolver.ResolverQueryLoggingConfigAssociation(
                f"{self.scope}ResolverQueryLogConfigAssociation",
                ResolverQueryLogConfigId=Ref(resolver_query_log_config_param),
                ResourceId=Ref(vpc),
            )
        )

        flow_logs = FlowLogs(
            scope=f"{self.scope}",
            vpc=Ref(vpc),
            flow_logs_bucket=Ref(flow_logs_bucket_param),
        )
        flow_logs.add_resources(template)

        igw = template.add_resource(
            ec2.InternetGateway(
                f"{self.scope}InternetGateway",
                Tags=[Tag("Name", Sub("${AWS::StackName}-igw"))],
            )
        )

        gw_attach = template.add_resource(
            ec2.VPCGatewayAttachment(
                f"{self.scope}AttachGateway",
                VpcId=Ref(vpc),
                InternetGatewayId=Ref(igw),
            )
        )

        public_subnet_route_table = template.add_resource(
            ec2.RouteTable(
                f"{self.scope}PublicSubnetRouteTable",
                VpcId=Ref(vpc),
                Tags=[Tag("Name", Sub("${AWS::StackName}-public-subnet-route-table"))],
            )
        )

        template.add_resource(
            ec2.Route(
                f"{self.scope}PublicSubnetRoute",
                DependsOn=gw_attach,
                RouteTableId=Ref(public_subnet_route_table),
                DestinationCidrBlock="0.0.0.0/0",
                GatewayId=Ref(igw),
            )
        )

        self.public_subnets = []
        self.app_subnets = []
        app_rtbs = []
        self.data_subnets = []
        for i in range(self.num_azs):
            public_subnet = Subnet(
                scope=f"{self.scope}PublicSubnet",
                vpc=Ref(vpc),
                az_index=i,
                cidr_block=f"10.0.{i}.0/24",
                name="public",
            )
            public_subnet.add_resources(template)
            self.public_subnets.append(public_subnet)

            template.add_resource(
                ec2.SubnetRouteTableAssociation(
                    f"{self.scope}PublicSubnetRouteTableAssociation{i + 1}",
                    SubnetId=Ref(public_subnet.subnet),
                    RouteTableId=Ref(public_subnet_route_table),
                )
            )

            eip = template.add_resource(
                ec2.EIP(
                    f"{self.scope}NatEIP{i + 1}",
                    Domain="vpc",
                    Condition=use_nat_condition,
                    DependsOn=gw_attach,
                    PublicIpv4Pool="amazon",
                )
            )

            nat_gw = template.add_resource(
                ec2.NatGateway(
                    f"{self.scope}NatGateway{i + 1}",
                    AllocationId=GetAtt(eip, "AllocationId"),
                    SubnetId=Ref(public_subnet.subnet),
                    Condition=use_nat_condition,
                )
            )

            app_subnet = Subnet(
                scope=f"{self.scope}AppSubnet",
                vpc=Ref(vpc),
                az_index=i,
                cidr_block=f"10.0.{i + self.num_azs}.0/24",
                name="app",
            )
            app_subnet.add_resources(template)
            self.app_subnets.append(app_subnet)

            app_subnet_route_table = template.add_resource(
                ec2.RouteTable(
                    f"{self.scope}AppSubnetRouteTable{i + 1}",
                    VpcId=Ref(vpc),
                    Tags=[Tag("Name", Sub("${AWS::StackName}-app-subnet-route-table"))],
                )
            )
            template.add_resource(
                ec2.SubnetRouteTableAssociation(
                    f"{self.scope}AppSubnetRouteTableAssociation{i + 1}",
                    RouteTableId=Ref(app_subnet_route_table),
                    SubnetId=Ref(app_subnet.subnet),
                )
            )
            app_rtbs.append(app_subnet_route_table)

            template.add_resource(
                ec2.Route(
                    f"{self.scope}AppSubnetRoute{i + 1}",
                    RouteTableId=Ref(app_subnet_route_table),
                    DestinationCidrBlock="0.0.0.0/0",
                    NatGatewayId=Ref(nat_gw),
                    Condition=use_nat_condition,
                    DependsOn=gw_attach,
                )
            )

            data_subnet = Subnet(
                scope=f"{self.scope}DataSubnet",
                vpc=Ref(vpc),
                az_index=i,
                cidr_block=f"10.0.{i + self.num_azs * 2}.0/24",
                name="data",
            )
            data_subnet.add_resources(template)
            self.data_subnets.append(data_subnet)

        public_subnet_ingress: list[tuple[str | Ref, AWSHelperFn | str]] = [
            ("80", "0.0.0.0/0"),
            ("443", "0.0.0.0/0"),
            ("587", "0.0.0.0/0"),
            ("1024-65535", "0.0.0.0/0"),
        ]
        public_subnet_egress: list[tuple[str | Ref, AWSHelperFn | str]] = [
            ("1024-65535", "0.0.0.0/0"),
            ("443", "0.0.0.0/0"),
            ("587", "0.0.0.0/0"),
        ]
        for subnet in self.app_subnets:
            public_subnet_ingress.append(
                ("1024-65535", GetAtt(subnet.subnet, "CidrBlock"))
            )
            public_subnet_egress.append(("80", GetAtt(subnet.subnet, "CidrBlock")))
            public_subnet_egress.append(("443", GetAtt(subnet.subnet, "CidrBlock")))

        public_subnet_network_firewall = Nacl(
            scope=f"{self.scope}PublicSubnet",
            vpc_id=Ref(vpc),
            allow_ingress_from=public_subnet_ingress,
            allow_egress_to=public_subnet_egress,
            subnets=[s.subnet for s in self.public_subnets],
        )
        public_subnet_network_firewall.add_resources(template)

        data_subnet_ingress: list[tuple[str | Ref, AWSHelperFn | str]] = []
        data_subnet_egress: list[tuple[str | Ref, AWSHelperFn | str]] = []
        for subnet in self.app_subnets:
            data_subnet_ingress.append(
                (Ref(data_port_param), GetAtt(subnet.subnet, "CidrBlock"))
            )
            data_subnet_ingress.append(("2049", GetAtt(subnet.subnet, "CidrBlock")))
            data_subnet_egress.append(
                ("1024-65535", GetAtt(subnet.subnet, "CidrBlock"))
            )

        data_subnet_network_firewall = Nacl(
            scope=f"{self.scope}DataSubnet",
            vpc_id=Ref(vpc),
            allow_ingress_from=data_subnet_ingress,
            allow_egress_to=data_subnet_egress,
            subnets=[s.subnet for s in self.data_subnets],
        )
        data_subnet_network_firewall.add_resources(template)

        app_subnet_ingress: list[tuple[str | Ref, AWSHelperFn | str]] = [
            ("1024-65535", "0.0.0.0/0"),
        ]
        app_subnet_egress: list[tuple[str | Ref, AWSHelperFn | str]] = [
            ("443", "0.0.0.0/0"),
            ("587", "0.0.0.0/0"),
        ]
        for subnet in self.public_subnets:
            app_subnet_ingress.append(("80", GetAtt(subnet.subnet, "CidrBlock")))
            app_subnet_ingress.append(("443", GetAtt(subnet.subnet, "CidrBlock")))
            app_subnet_egress.append(("1024-65535", GetAtt(subnet.subnet, "CidrBlock")))

        for subnet in self.data_subnets:
            # app_subnet_egress.append(("443", GetAtt(subnet.subnet, "CidrBlock")))
            app_subnet_egress.append(("2049", GetAtt(subnet.subnet, "CidrBlock")))
            app_subnet_egress.append(
                (Ref(data_port_param), GetAtt(subnet.subnet, "CidrBlock"))
            )

        for subnet in self.app_subnets:
            app_subnet_ingress.append(("443", GetAtt(subnet.subnet, "CidrBlock")))
            app_subnet_egress.append(("443", GetAtt(subnet.subnet, "CidrBlock")))
            app_subnet_ingress.append(("8000", GetAtt(subnet.subnet, "CidrBlock")))
            app_subnet_egress.append(("8000", GetAtt(subnet.subnet, "CidrBlock")))
            app_subnet_ingress.append(
                ("1024-65535", GetAtt(subnet.subnet, "CidrBlock"))
            )
            app_subnet_egress.append(("1024-65535", GetAtt(subnet.subnet, "CidrBlock")))

        app_subnet_network_firewall = Nacl(
            scope=f"{self.scope}AppSubnet",
            vpc_id=Ref(vpc),
            allow_ingress_from=app_subnet_ingress,
            allow_egress_to=app_subnet_egress,
            subnets=[s.subnet for s in self.app_subnets],
        )
        app_subnet_network_firewall.add_resources(template)

        vpc_endpoints_sg = template.add_resource(
            ec2.SecurityGroup(
                f"{self.scope}VpcEndpointsSecurityGroup",
                VpcId=Ref(vpc),
                GroupDescription="Allow HTTPS traffic from the VPC",
                SecurityGroupIngress=[
                    ec2.SecurityGroupRule(
                        IpProtocol="tcp",
                        FromPort=443,
                        ToPort=443,
                        CidrIp=GetAtt(vpc, "CidrBlock"),
                        Description="All ingress on 443 from the VPC CIDR",
                    )
                ],
                SecurityGroupEgress=[
                    ec2.SecurityGroupRule(
                        IpProtocol="-1",
                        CidrIp="127.0.0.1/32",
                        Description="Only allow egress to localhost (and prevent create of the default allow-all egress rule)",
                    )
                ],
            )
        )
        self.vpc_endpoint_security_group = vpc_endpoints_sg

        template.add_resource(
            ec2.VPCEndpoint(
                f"{self.scope}SecretsManagerVpcEndpoint",
                ServiceName=Sub("com.amazonaws.${AWS::Region}.secretsmanager"),
                VpcId=Ref(vpc),
                VpcEndpointType="Interface",
                PrivateDnsEnabled=True,
                SecurityGroupIds=[Ref(vpc_endpoints_sg)],
                SubnetIds=[Ref(subnet.subnet) for subnet in self.app_subnets],
            )
        )
        template.add_resource(
            ec2.VPCEndpoint(
                f"{self.scope}KmsManagerVpcEndpoint",
                ServiceName=Sub("com.amazonaws.${AWS::Region}.kms"),
                VpcId=Ref(vpc),
                VpcEndpointType="Interface",
                PrivateDnsEnabled=True,
                SecurityGroupIds=[Ref(vpc_endpoints_sg)],
                SubnetIds=[Ref(subnet.subnet) for subnet in self.app_subnets],
            )
        )

        template.add_resource(
            ec2.VPCEndpoint(
                f"{self.scope}EcrDkrVpcEndpoint",
                ServiceName=Sub("com.amazonaws.${AWS::Region}.ecr.dkr"),
                VpcId=Ref(vpc),
                VpcEndpointType="Interface",
                PrivateDnsEnabled=True,
                SecurityGroupIds=[Ref(vpc_endpoints_sg)],
                SubnetIds=[Ref(subnet.subnet) for subnet in self.app_subnets],
            )
        )

        template.add_resource(
            ec2.VPCEndpoint(
                f"{self.scope}EcrApiVpcEndpoint",
                ServiceName=Sub("com.amazonaws.${AWS::Region}.ecr.api"),
                VpcId=Ref(vpc),
                VpcEndpointType="Interface",
                PrivateDnsEnabled=True,
                SecurityGroupIds=[Ref(vpc_endpoints_sg)],
                SubnetIds=[Ref(subnet.subnet) for subnet in self.app_subnets],
            )
        )

        template.add_resource(
            ec2.VPCEndpoint(
                f"{self.scope}LogsVpcEndpoint",
                ServiceName=Sub("com.amazonaws.${AWS::Region}.logs"),
                VpcId=Ref(vpc),
                VpcEndpointType="Interface",
                PrivateDnsEnabled=True,
                SecurityGroupIds=[Ref(vpc_endpoints_sg)],
                SubnetIds=[Ref(subnet.subnet) for subnet in self.app_subnets],
            )
        )

        template.add_resource(
            ec2.VPCEndpoint(
                f"{self.scope}SqsVpcEndpoint",
                ServiceName=Sub("com.amazonaws.${AWS::Region}.sqs"),
                VpcId=Ref(vpc),
                VpcEndpointType="Interface",
                PrivateDnsEnabled=True,
                SecurityGroupIds=[Ref(vpc_endpoints_sg)],
                SubnetIds=[Ref(subnet.subnet) for subnet in self.app_subnets],
            )
        )

        template.add_resource(
            ec2.VPCEndpoint(
                f"{self.scope}SsmVpcEndpoint",
                ServiceName=Sub("com.amazonaws.${AWS::Region}.ssm"),
                VpcId=Ref(vpc),
                VpcEndpointType="Interface",
                PrivateDnsEnabled=True,
                SecurityGroupIds=[Ref(vpc_endpoints_sg)],
                SubnetIds=[Ref(subnet.subnet) for subnet in self.app_subnets],
            )
        )

        template.add_resource(
            ec2.VPCEndpoint(
                f"{self.scope}SsmMessagesVpcEndpoint",
                ServiceName=Sub("com.amazonaws.${AWS::Region}.ssmmessages"),
                VpcId=Ref(vpc),
                VpcEndpointType="Interface",
                PrivateDnsEnabled=True,
                SecurityGroupIds=[Ref(vpc_endpoints_sg)],
                SubnetIds=[Ref(subnet.subnet) for subnet in self.app_subnets],
            )
        )

        template.add_resource(
            ec2.VPCEndpoint(
                f"{self.scope}Ec2MessagesVpcEndpoint",
                ServiceName=Sub("com.amazonaws.${AWS::Region}.ec2messages"),
                VpcId=Ref(vpc),
                VpcEndpointType="Interface",
                PrivateDnsEnabled=True,
                SecurityGroupIds=[Ref(vpc_endpoints_sg)],
                SubnetIds=[Ref(subnet.subnet) for subnet in self.app_subnets],
            )
        )
        template.add_resource(
            ec2.VPCEndpoint(
                f"{self.scope}GuardDutyVpcEndpoint",
                ServiceName=Sub("com.amazonaws.${AWS::Region}.guardduty-data"),
                VpcId=Ref(vpc),
                VpcEndpointType="Interface",
                PrivateDnsEnabled=True,
                SecurityGroupIds=[Ref(vpc_endpoints_sg)],
                SubnetIds=[Ref(subnet.subnet) for subnet in self.app_subnets],
            )
        )

        template.add_resource(
            ec2.VPCEndpoint(
                f"{self.scope}S3VpcEndpoint",
                ServiceName=Sub("com.amazonaws.${AWS::Region}.s3"),
                VpcId=Ref(vpc),
                VpcEndpointType="Gateway",
                RouteTableIds=[Ref(route_table) for route_table in app_rtbs],
            )
        )

        template.add_output(
            Output(
                "VpcId",
                Value=Ref(vpc),
                Description="VPC ID",
            )
        )
        for i, subnet in enumerate(self.public_subnets):
            template.add_output(
                Output(
                    f"PublicSubnet{i + 1}",
                    Value=Ref(subnet.subnet),
                    Description=f"Public subnet {i + 1}",
                )
            )
        for i, subnet in enumerate(self.app_subnets):
            template.add_output(
                Output(
                    f"AppSubnet{i + 1}",
                    Value=Ref(subnet.subnet),
                    Description=f"App subnet {i + 1}",
                )
            )
        for i, subnet in enumerate(self.data_subnets):
            template.add_output(
                Output(
                    f"DataSubnet{i + 1}",
                    Value=Ref(subnet.subnet),
                    Description=f"Data subnet {i + 1}",
                )
            )
        template.add_output(
            Output(
                "VpcEndpointsSecurityGroup",
                Value=Ref(vpc_endpoints_sg),
                Description="Vpc endpoints security group",
            )
        )

        return template


def main():
    t = Template()
    t.set_description("VPC with public, app, and data subnets")
    vpc = Vpc(scope="", num_azs=2)
    vpc.add_resources(t)
    print(t.to_yaml())


if __name__ == "__main__":
    main()
