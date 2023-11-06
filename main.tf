terraform {
  cloud {
    organization = "Shadid-test"

    workspaces {
      name = "WorkloadAccount"
    }
  }
#  required_providers {
#    aws = {
#      source  = "hashicorp/aws"
#      version = "~> 4.16"
#    }
#  }
#
#  required_version = ">= 1.2.0"
}

provider "aws" {
  region  = "ap-southeast-2"
  #profile = "AWSAdministratorAccess-151435804697"
}

data "terraform_remote_state" "network" {
  backend = "remote"

  config = {
    organization = var.tfc_org_name
    workspaces = {
          name = var.tfc_network_workspace_name
    }
  }
}


locals {
  DEPLOYVPC1 = var.vpc1name != ""
  DEPLOYVPC2 = var.vpc2name != ""
  DEPLOYVPC3 = var.vpc3name != ""

  ATTACHVPC1 = var.vpc1attach == true
  ATTACHVPC2 = var.vpc2attach == true
  ATTACHVPC3 = var.vpc3attach == true
}

##########################################################
# Shared TGW from Network account
##########################################################

data "aws_ec2_transit_gateway" "shared_transit_gateway" {
  filter {
    name   = "owner-id"
    values = [var.NetworkAccountID]
}
}
output "shared_transit_gateway" {
  value = data.aws_ec2_transit_gateway.shared_transit_gateway.id
}


#--------------------------------------------------
# Deploy the Workload VPCs
#--------------------------------------------------

#VPC1
resource "aws_vpc" "VPC1" {
  count = local.DEPLOYVPC1 ? 1 : 0

  cidr_block           = var.vpc1cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = var.vpc1name
  }
}

#Create Transit subnet 1 for TGW attachment
resource "aws_subnet" "VPC1SubnetTransit1" {
  count = local.DEPLOYVPC1 ? 1 : 0

  vpc_id                 = aws_vpc.VPC1[0].id
  cidr_block             = cidrsubnet(aws_vpc.VPC1[0].cidr_block, 10, 0)
  availability_zone      = var.az1

  tags = {
    Name = "TRANSIT-AZ1"
  }
}

#Create Transit subnet 2 for TGW attachment

resource "aws_subnet" "VPC1SubnetTransit2" {
  count = local.DEPLOYVPC1 ? 1 : 0

  vpc_id                 = aws_vpc.VPC1[0].id
  cidr_block             = cidrsubnet(aws_vpc.VPC1[0].cidr_block, 10, 1)
  availability_zone      = var.az2

  tags = {
    Name = "TRANSIT-AZ2"
  }
}

#Create Private subnet 1

resource "aws_subnet" "VPC1PrivateSubnet1" {
  count = local.DEPLOYVPC1 ? 1 : 0

  vpc_id                 = aws_vpc.VPC1[0].id
  cidr_block             = cidrsubnet(aws_vpc.VPC1[0].cidr_block, 10, 2)
  availability_zone      = var.az1

  tags = {
    Name = "PRIVATE-AZ1"
  }
}

#Create Private subnet 2

resource "aws_subnet" "VPC1PrivateSubnet2" {
  count = local.DEPLOYVPC1 ? 1 : 0

  vpc_id                 = aws_vpc.VPC1[0].id
  cidr_block             = cidrsubnet(aws_vpc.VPC1[0].cidr_block, 10, 3)
  availability_zone      = var.az3

  tags = {
    Name = "PRIVATE-AZ3"
  }
}

# Create the VPC route table
resource "aws_route_table" "VPC1RouteTable" {
  count = local.DEPLOYVPC1 ? 1 : 0

  vpc_id = aws_vpc.VPC1[0].id
}

# Add the default route
resource "aws_route" "VPC1Route1" {
  count = local.DEPLOYVPC1 ? 1 : 0

  route_table_id         = aws_route_table.VPC1RouteTable[0].id
  destination_cidr_block = "0.0.0.0/0"
  transit_gateway_id     = data.terraform_remote_state.network.outputs.TGWID

  depends_on = [aws_ec2_transit_gateway_vpc_attachment.VPC1TransitGatewayAttach]
}

# Associate the route table with subnets
resource "aws_route_table_association" "VPC1RouteTableAssociation1" {
  count = local.DEPLOYVPC1 ? 1 : 0

  route_table_id = aws_route_table.VPC1RouteTable[0].id
  subnet_id      = aws_subnet.VPC1PrivateSubnet1[0].id
}

resource "aws_route_table_association" "VPC1RouteTableAssociation2" {
  count = local.DEPLOYVPC1 ? 1 : 0

  route_table_id = aws_route_table.VPC1RouteTable[0].id
  subnet_id      = aws_subnet.VPC1PrivateSubnet2[0].id
}

#############################################################
#VPC-TGW Attachment
#############################################################
resource "aws_ec2_transit_gateway_vpc_attachment" "VPC1TransitGatewayAttach" {
  count = local.DEPLOYVPC1 ? 1 : 0

  subnet_ids        = [
    aws_subnet.VPC1SubnetTransit1[0].id,
    aws_subnet.VPC1SubnetTransit2[0].id
  ]
  transit_gateway_id = data.terraform_remote_state.network.outputs.TGWID
  vpc_id            = aws_vpc.VPC1[0].id
}
