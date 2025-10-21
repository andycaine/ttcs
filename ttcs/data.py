from dataclasses import dataclass
from troposphere import (
    AWSHelperFn,
    Equals,
    Condition,
    If,
    Template,
    Ref,
    Parameter,
    GetAtt,
    Output,
)
from troposphere import ec2
from troposphere import rds
from troposphere import efs


@dataclass
class FileSystem:
    vpc_id: str | AWSHelperFn
    subnet_ids: list[str | AWSHelperFn]

    def add_resources(self, t: Template) -> Template:
        file_system_param = t.add_parameter(
            Parameter("FileSystemId", Type="String", Description="EFS ID", Default="")
        )
        t.add_condition(
            name="CreateFileSystem",
            condition=Equals(Ref(file_system_param), ""),
        )
        self.file_system = t.add_resource(
            efs.FileSystem(
                "AppMediaEFS",
                Condition="CreateFileSystem",
                Encrypted=True,
                PerformanceMode="generalPurpose",
                FileSystemProtection=efs.FileSystemProtection(
                    ReplicationOverwriteProtection="ENABLED"
                ),
                LifecyclePolicies=[
                    efs.LifecyclePolicy(TransitionToIA="AFTER_30_DAYS"),
                    efs.LifecyclePolicy(
                        TransitionToPrimaryStorageClass="AFTER_1_ACCESS"
                    ),
                ],
                ThroughputMode="bursting",
                BackupPolicy=efs.BackupPolicy(Status="ENABLED"),
            )
        )

        self.fs_security_group = t.add_resource(
            ec2.SecurityGroup(
                "AppMediaSG",
                GroupDescription="Security group for app media EFS",
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
        for i, subnet_id in enumerate(self.subnet_ids):
            t.add_resource(
                efs.MountTarget(
                    f"AppMediaMountTarget{i + 1}",
                    FileSystemId=If(
                        "CreateFileSystem",
                        Ref(self.file_system),
                        Ref(file_system_param),
                    ),
                    SubnetId=subnet_id,
                    SecurityGroups=[Ref(self.fs_security_group)],
                )
            )
        t.add_output(
            Output(
                "FileSystemSecurityGroupId",
                Value=Ref(self.fs_security_group),
                Description="FileSystem security group ID",
            )
        )
        t.add_output(
            Output(
                "FileSystemId",
                Value=Ref(self.file_system),
                Condition="CreateFileSystem",
                Description="EFS ID",
            )
        )
        return t


@dataclass
class DbInstance:
    vpc_id: str | AWSHelperFn
    subnet_ids: list[str | AWSHelperFn]
    restore: bool = False

    def add_resources(self, t: Template) -> Template:
        db_subnet_group = t.add_resource(
            rds.DBSubnetGroup(
                "DbSubnetGroup",
                DBSubnetGroupDescription="Subnet group for RDS instance",
                SubnetIds=self.subnet_ids,
            )
        )
        db_sg = t.add_resource(
            ec2.SecurityGroup(
                "DbSecurityGroup",
                GroupDescription="Security group for RDS instance",
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
        self.db_security_group = db_sg

        # t.add_resource(
        #    rds.OptionGroup(
        #        "PCHOptionGroup",
        #        EngineName="mysql",
        #        MajorEngineVersion="8.4",
        #        OptionGroupName="pch-option-group-8-4",
        #        OptionGroupDescription="Option group for PCH MySQL 8.4 RDS instances",
        #        OptionConfigurations=[],
        #    )
        # )

        kwargs = dict(
            AllocatedStorage="10",
            AutoMinorVersionUpgrade=True,
            BackupRetentionPeriod=7,
            PreferredBackupWindow="06:00-07:00",
            CACertificateIdentifier="rds-ca-rsa2048-g1",
            CopyTagsToSnapshot=True,
            DBParameterGroupName="default.mysql8.0",
            OptionGroupName="default:mysql-8-0",
            DBInstanceClass="db.t4g.medium",
            Engine="mysql",
            EngineVersion="8.0.43",
            NetworkType="IPV4",
            MultiAZ=True,
            Port=3306,
            StorageType="gp2",
            DeletionProtection=True,
            PreferredMaintenanceWindow="sun:07:00-sun:08:00",
            EnablePerformanceInsights=False,
            DBSubnetGroupName=Ref(db_subnet_group),
            ManageMasterUserPassword=True,
            VPCSecurityGroups=[GetAtt(db_sg, "GroupId")],
            EnableIAMDatabaseAuthentication=False,
            PubliclyAccessible=False,
            EnableCloudwatchLogsExports=["error"],
            StorageEncrypted=True,
            Tags=[{"Key": "workload-type", "Value": "production"}],
        )
        if self.restore:
            db_snapshot_param = t.add_parameter(
                Parameter(
                    "DBSnapshotIdentifier",
                    Type="String",
                    Description="DB snapshot identifier",
                )
            )
            kwargs["DBSnapshotIdentifier"] = Ref(db_snapshot_param)
        else:
            db_name_param = t.add_parameter(
                Parameter("DBName", Type="String", Description="DB name")
            )
            db_master_username_param = t.add_parameter(
                Parameter(
                    "DBMasterUsernameName",
                    Type="String",
                    Description="DB master username",
                )
            )
            kwargs["DBName"] = Ref(db_name_param)
            db_master_username_param = t.add_parameter(
                Parameter(
                    "DbMasterUsername",
                    Type="String",
                    NoEcho=True,
                    Description="DB master username",
                )
            )
            kwargs["MasterUsername"] = Ref(db_master_username_param)

        db = t.add_resource(rds.DBInstance("AppDb", **kwargs))
        t.add_output(
            Output(
                "DbEndpointAddress",
                Value=GetAtt(db, "Endpoint.Address"),
                Description="DB endpoint address",
            )
        )
        t.add_output(
            Output(
                "DbInstanceName",
                Value=Ref(db),
                Description="DB instance name",
            )
        )

        return t


def main():
    t = Template()
    t.set_description("RDS and EFS data tier for a three-tier web-app stack")

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

    db_instance = DbInstance(
        vpc_id=Ref(vpc_id_param),
        subnet_ids=[Ref(subnet_id_1_param), Ref(subnet_id_2_param)],
        restore=True,
    )
    db_instance.add_resources(t)

    filesystem = FileSystem(
        vpc_id=Ref(vpc_id_param),
        subnet_ids=[Ref(subnet_id_1_param), Ref(subnet_id_2_param)],
    )
    filesystem.add_resources(t)

    t.add_output(
        Output(
            "DbSecurityGroupId",
            Value=Ref(db_instance.db_security_group),
            Description="DB security group ID",
        )
    )
    print(t.to_yaml())


if __name__ == "__main__":
    main()
