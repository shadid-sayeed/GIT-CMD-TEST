terraform {
  cloud {
    organization = "Shadid-test"

    workspaces {
      name = "NetworkAccount"
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
#  profile = "AWSAdministratorAccess-672268511566"
}



locals {
  VTGWATTACHED    = var.vtgwattachmentid != ""
  DeployDXGW      = var.dxgatewayname != ""
  DeployVPN1      = var.vpn1name != ""
  DeployVPN2      = var.vpn2name != ""
  DeployVPN3      = var.vpn3name != ""
  DeployVPN4      = var.vpn4name != ""
#  DeployAccount2  = var.targetaccount2 != ""
#  DeployAccount3  = var.targetaccount3 != ""
#  DeployAccount4  = var.targetaccount4 != ""
   tf_assumed_role = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${split("/", data.aws_caller_identity.current.arn)[1]}" 
}



#--------------------------------------------------
# Create Prefix Lists
#--------------------------------------------------

resource "aws_ec2_managed_prefix_list" "VMCPrefixList" {
#  count     = local.VTGWATTACHED ? 1 : 0
  name      = "vmc-subnets"
  address_family = "IPv4"
  max_entries = 100

  tags = {
    Name = "vmc-subnets"
  }
}

resource "aws_ec2_managed_prefix_list" "RFC1918PrefixList" {
  name      = "rfc1918"
  address_family = "IPv4"
  max_entries = 3

  entry {
    cidr = "10.0.0.0/8"
  }
  entry {
    cidr = "192.168.0.0/16"
  }
  entry {
    cidr = "172.16.0.0/12"
  }

  tags = {
    Name = "rfc1918"
  }
}


#--------------------------------------------------
# Deploy the Security VPC
#--------------------------------------------------

resource "aws_vpc" "SecVPC" {
  cidr_block           = var.securityvpccidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  
  tags = {
    Name = var.securityvpcname
  }
}

resource "aws_subnet" "SecSubnetTransit1" {
  vpc_id            = aws_vpc.SecVPC.id
  cidr_block        = cidrsubnet(aws_vpc.SecVPC.cidr_block, 10, 0)
  availability_zone = var.az1
  
  tags = {
    Name = "TRANSIT-AZ1"
  }
}

resource "aws_subnet" "SecSubnetTransit2" {
  vpc_id            = aws_vpc.SecVPC.id
  cidr_block        = cidrsubnet(aws_vpc.SecVPC.cidr_block, 10, 1)
  availability_zone = var.az2
  
  tags = {
    Name = "TRANSIT-AZ2"
  }
}

resource "aws_subnet" "SecSubnetManagement1" {
  vpc_id            = aws_vpc.SecVPC.id
  cidr_block        = cidrsubnet(aws_vpc.SecVPC.cidr_block, 10, 2)
  availability_zone = var.az1
  
  tags = {
    Name = "MANAGEMENT-AZ1"
  }
}

resource "aws_subnet" "SecSubnetManagement2" {
  vpc_id            = aws_vpc.SecVPC.id
  cidr_block        = cidrsubnet(aws_vpc.SecVPC.cidr_block, 10, 3)
  availability_zone = var.az2
  
  tags = {
    Name = "MANAGEMENT-AZ2"
  }
}

resource "aws_subnet" "SecSubnetHeartbeat1" {
  vpc_id            = aws_vpc.SecVPC.id
  cidr_block        = cidrsubnet(aws_vpc.SecVPC.cidr_block, 10, 4)
  availability_zone = var.az1
  
  tags = {
    Name = "HEARTBEAT-AZ1"
  }
}

resource "aws_subnet" "SecSubnetHeartbeat2" {
  vpc_id            = aws_vpc.SecVPC.id
  cidr_block        = cidrsubnet(aws_vpc.SecVPC.cidr_block, 10, 5)
  availability_zone = var.az2
  
  tags = {
    Name = "HEARTBEAT-AZ2"
  }
}

#Private Subnet

resource "aws_subnet" "SecSubnetPrivate1" {
  vpc_id            = aws_vpc.SecVPC.id
  cidr_block        = cidrsubnet(aws_vpc.SecVPC.cidr_block, 10, 6)
  availability_zone = var.az1
  
  tags = {
    Name = "PRIVATE-AZ1"
  }
}

resource "aws_subnet" "SecSubnetPrivate2" {
  vpc_id            = aws_vpc.SecVPC.id
  cidr_block        = cidrsubnet(aws_vpc.SecVPC.cidr_block, 10, 7)
  availability_zone = var.az2
  
  tags = {
    Name = "PRIVATE-AZ2"
  }
}

#Create Public subnet 1

resource "aws_subnet" "SecSubnetPublic1" {
  vpc_id            = aws_vpc.SecVPC.id
  cidr_block        = cidrsubnet(aws_vpc.SecVPC.cidr_block, 10, 8)
  availability_zone = var.az1
  
  tags = {
    Name = "PUBLIC-AZ1"
  }
}

resource "aws_subnet" "SecSubnetPublic2" {
  vpc_id            = aws_vpc.SecVPC.id
  cidr_block        = cidrsubnet(aws_vpc.SecVPC.cidr_block, 10, 9)
  availability_zone = var.az2
  
  tags = {
    Name = "PUBLIC-AZ2"
  }
}

#Create VPC route tables

resource "aws_route_table" "SecRouteTableTransit" {
  vpc_id = aws_vpc.SecVPC.id
  
  tags = {
    Name = "TRANSIT"
  }
}

resource "aws_route_table" "SecRouteTableManagement" {
  vpc_id = aws_vpc.SecVPC.id
  
  tags = {
    Name = "MANAGEMENT"
  }
}

resource "aws_route_table" "SecRouteTableHeartbeat" {
  vpc_id = aws_vpc.SecVPC.id
  
  tags = {
    Name = "HEARTBEAT"
  }
}

resource "aws_route_table" "SecRouteTablePrivate" {
  vpc_id = aws_vpc.SecVPC.id
  
  tags = {
    Name = "PRIVATE"
  }
}

resource "aws_route_table" "SecRouteTablePublic" {
  vpc_id = aws_vpc.SecVPC.id
  
  tags = {
    Name = "PUBLIC"
  }
}

#Associate route tables
resource "aws_route_table_association" "VPCRouteTableAssociation1" {
  route_table_id = aws_route_table.SecRouteTableTransit.id
  subnet_id      = aws_subnet.SecSubnetTransit1.id
}

resource "aws_route_table_association" "VPCRouteTableAssociation2" {
  route_table_id = aws_route_table.SecRouteTableTransit.id
  subnet_id      = aws_subnet.SecSubnetTransit2.id
}

resource "aws_route_table_association" "VPCRouteTableAssociation3" {
  route_table_id = aws_route_table.SecRouteTableManagement.id
  subnet_id      = aws_subnet.SecSubnetManagement1.id
}

resource "aws_route_table_association" "VPCRouteTableAssociation4" {
  route_table_id = aws_route_table.SecRouteTableManagement.id
  subnet_id      = aws_subnet.SecSubnetManagement2.id
}

resource "aws_route_table_association" "VPCRouteTableAssociation5" {
  route_table_id = aws_route_table.SecRouteTablePrivate.id
  subnet_id      = aws_subnet.SecSubnetPrivate1.id
}

resource "aws_route_table_association" "VPCRouteTableAssociation6" {
  route_table_id = aws_route_table.SecRouteTablePrivate.id
  subnet_id      = aws_subnet.SecSubnetPrivate2.id
}

resource "aws_route_table_association" "VPCRouteTableAssociation7" {
  route_table_id = aws_route_table.SecRouteTablePublic.id
  subnet_id      = aws_subnet.SecSubnetPublic1.id
}

resource "aws_route_table_association" "VPCRouteTableAssociation8" {
  route_table_id = aws_route_table.SecRouteTablePublic.id
  subnet_id      = aws_subnet.SecSubnetPublic2.id
}

resource "aws_route_table_association" "VPCRouteTableAssociation9" {
  route_table_id = aws_route_table.SecRouteTableHeartbeat.id
  subnet_id      = aws_subnet.SecSubnetHeartbeat1.id
}

resource "aws_route_table_association" "VPCRouteTableAssociation10" {
  route_table_id = aws_route_table.SecRouteTableHeartbeat.id
  subnet_id      = aws_subnet.SecSubnetHeartbeat2.id
}

###################################################################
#Deploy IGW
###################################################################

resource "aws_internet_gateway" "igw1" { 
  vpc_id = aws_vpc.SecVPC.id
}

####################################################
# Deploy the Transit Gateway
####################################################

resource "aws_ec2_transit_gateway" "TransitGateway" {
  amazon_side_asn               = var.tgwasn
  description                   = "CodeDeployTest"
  auto_accept_shared_attachments = "enable"
  default_route_table_association = "disable"
  default_route_table_propagation = "disable"
  dns_support                   = "enable"
  vpn_ecmp_support              = "enable"

  tags = {
    Name = var.tgwname
  }
}

##TGW  Route table for Security VPC
resource "aws_ec2_transit_gateway_route_table" "TGWRouteTableSecurity" {
  transit_gateway_id = aws_ec2_transit_gateway.TransitGateway.id
  tags = {
    Name = "SECURITY"
  }
}

#TGW Main Route Table
resource "aws_ec2_transit_gateway_route_table" "TGWRouteTableMain" {
  transit_gateway_id = aws_ec2_transit_gateway.TransitGateway.id
  tags = {
    Name = "MAIN"
  }
}

#TGW Route table for VPN Connection
resource "aws_ec2_transit_gateway_route_table" "TGWRouteTableVPN" {
  transit_gateway_id = aws_ec2_transit_gateway.TransitGateway.id
  tags = {
    Name = "VPN"
  }
}


##--------------------------------------------------
## Deploy VPN Connection 1 (if vpn1name specified)
##--------------------------------------------------
# Create CGW 
resource "aws_customer_gateway" "VPN1CustomerGateway" {
  count  = local.DeployVPN1 ? 1 : 0
  bgp_asn   = var.vpn1remoteasn
  ip_address = var.vpn1remoteip
  
  tags = {
    Name = var.vpn1name
  }
  
  type = "ipsec.1"
}

#Create Site-2-Site VPN
resource "aws_vpn_connection" "VPN1Connection" {
  count  = local.DeployVPN1 ? 1 : 0
  customer_gateway_id = aws_customer_gateway.VPN1CustomerGateway[0].id
  transit_gateway_id  = aws_ec2_transit_gateway.TransitGateway.id
  local_ipv4_network_cidr = var.awssummarycidr
  remote_ipv4_network_cidr = var.vpn1allowedcidr
  tags = {
    Name = var.vpn1name
  }
  
  type = "ipsec.1"
}

#
#
##----------------------------------------------------------------
## Deploy Direct Connect Gateway (if dxgatewayname specified)
##----------------------------------------------------------------

#Create DX Gateway
resource "aws_dx_gateway" "DXGW-1" {
  name = var.dxgatewayname
  amazon_side_asn = var.dxgatewayasn  # Replace with your desired ASN
}

#Create DXGW Associaiton
resource "aws_dx_gateway_association" "DXGWAssociation" {
  dx_gateway_id               = aws_dx_gateway.DXGW-1.id
  #dx_gateway_owner_account_id = aws_dx_gateway.DXGW-1.owner_account_id
  associated_gateway_id       = aws_ec2_transit_gateway.TransitGateway.id
  allowed_prefixes = [
  var.awssummarycidr
  ]
}
#
#
#####################################################################
## TGW Attachments
#####################################################################

#TGW-VPC attachments
resource "aws_ec2_transit_gateway_vpc_attachment" "TransitGatewayAttachmentSecVPC" {
  subnet_ids         = [aws_subnet.SecSubnetTransit1.id, aws_subnet.SecSubnetTransit2.id]
  transit_gateway_id = aws_ec2_transit_gateway.TransitGateway.id
  vpc_id             = aws_vpc.SecVPC.id

  depends_on = [
    aws_ec2_transit_gateway.TransitGateway
  ]
}

#TGW-VPN Attachment
data "aws_ec2_transit_gateway_vpn_attachment" "VPN1TGWAttachment" {
  transit_gateway_id = aws_ec2_transit_gateway.TransitGateway.id
  vpn_connection_id  = aws_vpn_connection.VPN1Connection[0].id
}

#TGW-DXGW Attachment
data "aws_ec2_transit_gateway_dx_gateway_attachment" "TGWDXGWAttachment" {
  transit_gateway_id = aws_ec2_transit_gateway.TransitGateway.id
  dx_gateway_id      = aws_dx_gateway.DXGW-1.id
  depends_on = [
   aws_dx_gateway_association.DXGWAssociation
   ]
}



####################################################################
# TGW Attachment - Route table associaiton
####################################################################

#Associate Security VPC attachment with TGW route table 
resource "aws_ec2_transit_gateway_route_table_association" "TGWSecAssociation" {
  transit_gateway_attachment_id = aws_ec2_transit_gateway_vpc_attachment.TransitGatewayAttachmentSecVPC.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.TGWRouteTableSecurity.id
}

#Associate VPN Attachment to Route table

resource "aws_ec2_transit_gateway_route_table_association" "TGWVPNRTBAssociation" {
  transit_gateway_attachment_id = data.aws_ec2_transit_gateway_vpn_attachment.VPN1TGWAttachment.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.TGWRouteTableVPN.id
}

#Associate DXGW attachment to Route table

resource "aws_ec2_transit_gateway_route_table_association" "TGWDXGWRTBAssociation" {
  transit_gateway_attachment_id = data.aws_ec2_transit_gateway_dx_gateway_attachment.TGWDXGWAttachment.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.TGWRouteTableMain.id
}

####################################################################
#Route Table Propagation
####################################################################

#Propagate VPN attachment to TGWRouteTableSecurity
#
#resource "aws_ec2_transit_gateway_route_table_propagation" "VPN1AttachmentPropagationtoTGWSecurityRouteTable" {
#  transit_gateway_attachment_id  = data.aws_ec2_transit_gateway_vpn_attachment.VPN1TGWAttachment.id
#  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.TGWRouteTableSecurity.id
#}
#
##Propagate DXGW attachment to TGWRouteTableSecurity
#resource "aws_ec2_transit_gateway_route_table_propagation" "DXGWAttachmentPropagationtoTGWSecurityRouteTable" {
#  transit_gateway_attachment_id  = data.aws_ec2_transit_gateway_dx_gateway_attachment.TGWDXGWAttachment.id
#  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.TGWRouteTableSecurity.id
#
#}



####################################################################
#Add Route to Route tables
####################################################################

##Route for Main Route Table
resource "aws_ec2_transit_gateway_route" "RouteToSecVPC" {
  blackhole                     = false
  destination_cidr_block        = "0.0.0.0/0"
  transit_gateway_attachment_id = aws_ec2_transit_gateway_vpc_attachment.TransitGatewayAttachmentSecVPC.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.TGWRouteTableMain.id
  depends_on = [
     aws_ec2_transit_gateway_vpc_attachment.TransitGatewayAttachmentSecVPC
  ]
}
#
##Route for VPN Route table
resource "aws_ec2_transit_gateway_route" "AWSCIDRRouteToSecVPC" {
  blackhole                     = false
  destination_cidr_block        = var.awssummarycidr
  transit_gateway_attachment_id = aws_ec2_transit_gateway_vpc_attachment.TransitGatewayAttachmentSecVPC.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.TGWRouteTableVPN.id
  depends_on = [
     aws_ec2_transit_gateway_vpc_attachment.TransitGatewayAttachmentSecVPC
  ]
}

resource "aws_ec2_transit_gateway_prefix_list_reference" "RouteVPN1VMCPrefixList" {
  prefix_list_id                 = aws_ec2_managed_prefix_list.VMCPrefixList.id
  transit_gateway_attachment_id  = data.aws_ec2_transit_gateway_vpn_attachment.VPN1TGWAttachment.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.TGWRouteTableVPN.id
}

##Add VTGW Prefix list to TGWSecurity Route Table
resource "aws_ec2_transit_gateway_prefix_list_reference" "RouteVTGWPrefixList" {
  count     = local.VTGWATTACHED ? 1 : 0
  prefix_list_id                 = var.vtgwprefixlistid
  transit_gateway_attachment_id  = var.vtgwattachmentid
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.TGWRouteTableSecurity.id
}


#resource "aws_ec2_transit_gateway_route" "VMCCIDRRouteToSecVPC" {
#  blackhole                     = false
#  destination_cidr_block        = aws_ec2_managed_prefix_list.VMCPrefixList[*].id
#  transit_gateway_attachment_id = aws_ec2_transit_gateway_vpc_attachment.TransitGatewayAttachmentSecVPC.id
#  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.TGWRouteTableVPN.id
#  depends_on = [
#     aws_ec2_transit_gateway_vpc_attachment.TransitGatewayAttachmentSecVPC
#  ]
#}
#

##################################################################
##Share Transit Gateway
###################################################################
resource "aws_ram_resource_share" "tgw_share" {
  name                      = "TGWshare"
  allow_external_principals = false
}

resource "aws_ram_resource_association" "tgw-share-association" {
  resource_arn       = aws_ec2_transit_gateway.TransitGateway.arn
  resource_share_arn = aws_ram_resource_share.tgw_share.id
}

resource "aws_ram_principal_association" "shared_principals" {
  principal = var.orgid
  resource_share_arn = aws_ram_resource_share.tgw_share.arn
}

###########################################################
# Assign Default Association and propagation route table
###########################################################

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
resource "null_resource" "modify_tgw_to_enable_default_route_propagation_association" {
  triggers = {
    trigger            = jsonencode(aws_ec2_transit_gateway.TransitGateway)
    aws_region         = data.aws_region.current.name
	tf_caller_identity_arn = data.aws_caller_identity.current.arn
    tf_assumed_role        = local.tf_assumed_role
    transit_gateway_id = aws_ec2_transit_gateway.TransitGateway.id
	associationrtb = aws_ec2_transit_gateway_route_table.TGWRouteTableMain.id
	propagationrtb = aws_ec2_transit_gateway_route_table.TGWRouteTableSecurity.id
  }

  lifecycle {
    ignore_changes = [triggers["aws_region"], triggers["tf_caller_identity"], triggers["tf_assumed_role"], triggers["transit_gateway_id"], triggers["associationrtb"], triggers["propagationrtb"] ]
  }

  provisioner "local-exec" {
    interpreter = ["PowerShell", "-Command"]
    environment = {
      AWS_DEFAULT_REGION = self.triggers.aws_region
    }
 
   command = <<EOF
aws ec2 modify-transit-gateway --transit-gateway-id ${self.triggers.transit_gateway_id} --options "DefaultRouteTablePropagation=enable,PropagationDefaultRouteTableId=${self.triggers.propagationrtb}" --region ${self.triggers.aws_region}
aws ec2 modify-transit-gateway --transit-gateway-id ${self.triggers.transit_gateway_id} --options "DefaultRouteTableAssociation=enable,AssociationDefaultRouteTableId=${self.triggers.associationrtb}" --region ${self.triggers.aws_region}

   EOF
  }
  
#  provisioner "local-exec" {
#    when = destroy
#    interpreter = ["PowerShell", "-Command"]
#    environment = {
#      AWS_DEFAULT_REGION = self.triggers.aws_region
#    }
#   command = <<EOF
#aws ec2 modify-transit-gateway --transit-gateway-id ${self.triggers.transit_gateway_id} --options "DefaultRouteTablePropagation=disable,DefaultRouteTableAssociation=disable" --region ${self.triggers.aws_region}
##aws ec2 modify-transit-gateway --transit-gateway-id ${self.triggers.transit_gateway_id} --options DefaultRouteTableAssociation=disable --region ${self.triggers.aws_region}"
#aws ec2 delete-transit-gateway --transit-gateway-id ${self.triggers.transit_gateway_id}
#   EOF
#  }
#  depends_on = [
#  aws_ec2_transit_gateway_route_table_association.TGWSecAssociation,
#  aws_ec2_transit_gateway_route_table_association.TGWVPNRTBAssociation,
#  aws_ec2_transit_gateway_route_table_association.TGWDXGWRTBAssociation,
#  aws_ec2_transit_gateway_prefix_list_reference.RouteVTGWPrefixList
#  ]
}

###################################################
#Deploy Firewall
###################################################

#Create Security Groups for the firewall ENIs
resource "aws_security_group" "FirewallManagementSG" {
  name        = "Firewall-Management"
  description = "Firewall Management"
  vpc_id      = aws_vpc.SecVPC.id
}

resource "aws_security_group" "FirewallHeartbeatSG" {
  name        = "Firewall-Heartbeat"
  description = "Firewall Heartbeat"
  vpc_id      = aws_vpc.SecVPC.id
}

resource "aws_security_group" "FirewallPrivateSG" {
  name        = "Firewall-Private"
  description = "Firewall Private"
  vpc_id      = aws_vpc.SecVPC.id
}

resource "aws_security_group" "FirewallPublicSG" {
  name        = "Firewall-Public"
  description = "Firewall Public"
  vpc_id      = aws_vpc.SecVPC.id
}

#Create ENIs for firewalls

resource "aws_network_interface" "FirewallManagementENI1" {
  subnet_id        = aws_subnet.SecSubnetManagement1.id
  description      = "Firewall Management Interface"
  source_dest_check = false
  tags = {
    Name = "FIREWALL1-MGMT"
  }
  security_groups = [aws_security_group.FirewallManagementSG.id]
}

resource "aws_network_interface" "FirewallManagementENI2" {
  subnet_id        = aws_subnet.SecSubnetManagement2.id
  description      = "Firewall Management Interface"
  source_dest_check = false
  tags = {
    Name = "FIREWALL2-MGMT"
  }
  security_groups = [aws_security_group.FirewallManagementSG.id]
}

resource "aws_network_interface" "FirewallHeartbeatENI1" {
  subnet_id        = aws_subnet.SecSubnetHeartbeat1.id
  description      = "Firewall Heartbeat Interface"
  source_dest_check = false
  tags = {
    Name = "FIREWALL1-HB"
  }
  security_groups = [aws_security_group.FirewallHeartbeatSG.id]
}

resource "aws_network_interface" "FirewallHeartbeatENI2" {
  subnet_id        = aws_subnet.SecSubnetHeartbeat2.id
  description      = "Firewall Heartbeat Interface"
  source_dest_check = false
  tags = {
    Name = "FIREWALL2-HB"
  }
  security_groups = [aws_security_group.FirewallHeartbeatSG.id]
}

resource "aws_network_interface" "FirewallPrivateENI1" {
  subnet_id        = aws_subnet.SecSubnetPrivate1.id
  description      = "Firewall Private Interface"
  source_dest_check = false
  tags = {
    Name = "FIREWALL1-PRIV"
  }
  security_groups = [aws_security_group.FirewallPrivateSG.id]
}

resource "aws_network_interface" "FirewallPrivateENI2" {
  subnet_id        = aws_subnet.SecSubnetPrivate2.id
  description      = "Firewall Private Interface"
  source_dest_check = false
  tags = {
    Name = "FIREWALL2-PRIV"
  }
  security_groups = [aws_security_group.FirewallPrivateSG.id]
}

resource "aws_network_interface" "FirewallPublicENI1" {
  subnet_id        = aws_subnet.SecSubnetPublic1.id
  description      = "Firewall Public Interface"
  source_dest_check = false
  tags = {
    Name = "FIREWALL1-PUB"
  }
  security_groups = [aws_security_group.FirewallPublicSG.id]
  #secondary_private_ip_address_count = var.firewallsecondaryips
}

resource "aws_network_interface" "FirewallPublicENI2" {
  subnet_id        = aws_subnet.SecSubnetPublic2.id
  description      = "Firewall Public Interface"
  source_dest_check = false
  tags = {
    Name = "FIREWALL2-PUB"
  }
  security_groups = [aws_security_group.FirewallPublicSG.id]
  #secondary_private_ip_address_count = var.firewallsecondaryips
}

#Define Firewall IAM role

resource "aws_iam_role" "FirewallRole" {
  name = "FirewallRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "ec2.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "FirewallRolePolicy" {
  name        = "FirewallRolePolicy"
  description = "Firewall Role Policy"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Action = [
        "ec2:Describe*",
        "ec2:AssociateAddress",
        "ec2:AssignPrivateIpAddresses",
        "ec2:UnassignPrivateIpAddresses",
        "ec2:ReplaceRoute"
      ],
      Resource = "*",
      Condition = {
        StringEquals = {
          "aws:ec2InstanceSourceVPC" = aws_vpc.SecVPC.id
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "FirewallRoleAttachment" {
  policy_arn = aws_iam_policy.FirewallRolePolicy.arn
  role       = aws_iam_role.FirewallRole.name
}

resource "aws_iam_instance_profile" "FirewallInstanceProfile" {
  name = "FirewallInstanceProfile"

  role = aws_iam_role.FirewallRole.name
}

#Deploy Firewall Instance 1

resource "aws_instance" "FirewallInstance1" {
  depends_on = [
    aws_network_interface.FirewallPublicENI1,
    aws_network_interface.FirewallPrivateENI1,
    aws_network_interface.FirewallHeartbeatENI1,
    aws_network_interface.FirewallManagementENI1,
    aws_iam_instance_profile.FirewallInstanceProfile
  ]

  iam_instance_profile = aws_iam_instance_profile.FirewallInstanceProfile.name

  network_interface {
    network_interface_id = aws_network_interface.FirewallPublicENI1.id
    device_index         = 0
  }

  network_interface {
    network_interface_id = aws_network_interface.FirewallPrivateENI1.id
    device_index         = 1
  }

  network_interface {
    network_interface_id = aws_network_interface.FirewallHeartbeatENI1.id
    device_index         = 2
  }

  network_interface {
    network_interface_id = aws_network_interface.FirewallManagementENI1.id
    device_index         = 3
  }

  ami           = var.firewallimageid
  instance_type = var.firewallinstancetype

  root_block_device {
    #device_name = "/dev/sda1"
    volume_size = 2
    volume_type = "gp2"
    delete_on_termination = false
    encrypted = true
  }

  ebs_block_device {
    device_name = "/dev/sdb"
    volume_size = 30
    volume_type = "gp2"
    delete_on_termination = false
    encrypted = true
  }

  tags = {
    Name = "FIREWALL1"
  }
}


#Deploy Firewall Instance 2

resource "aws_instance" "FirewallInstance2" {
  depends_on = [
    aws_network_interface.FirewallPublicENI2,
    aws_network_interface.FirewallPrivateENI2,
    aws_network_interface.FirewallHeartbeatENI2,
    aws_network_interface.FirewallManagementENI2,
    aws_iam_instance_profile.FirewallInstanceProfile
  ]

  iam_instance_profile = aws_iam_instance_profile.FirewallInstanceProfile.name

  network_interface {
    network_interface_id = aws_network_interface.FirewallPublicENI2.id
    device_index         = 0
  }

  network_interface {
    network_interface_id = aws_network_interface.FirewallPrivateENI2.id
    device_index         = 1
  }

  network_interface {
    network_interface_id = aws_network_interface.FirewallHeartbeatENI2.id
    device_index         = 2
  }

  network_interface {
    network_interface_id = aws_network_interface.FirewallManagementENI2.id
    device_index         = 3
  }

  ami           = var.firewallimageid
  instance_type = var.firewallinstancetype

  root_block_device {
   # device_name = "/dev/sda1"
    volume_size = 2
    volume_type = "gp2"
    delete_on_termination = false
    encrypted = true
  }

  ebs_block_device {
    device_name = "/dev/sdb"
    volume_size = 30
    volume_type = "gp2"
    delete_on_termination = false
    encrypted = true
  }

  tags = {
    Name = "FIREWALL2"
  }
}

############################################################################
#Add routes to Security VPC
############################################################################

resource "aws_route" "TransitRoute1" {
  depends_on = [
    aws_network_interface.FirewallPrivateENI1,
    aws_instance.FirewallInstance1
  ]

  destination_cidr_block = "0.0.0.0/0"
  route_table_id         = aws_route_table.SecRouteTableTransit.id
  network_interface_id   = aws_network_interface.FirewallPrivateENI1.id
}

resource "aws_route" "PrivateRoute1" {
  depends_on = [
    aws_ec2_transit_gateway_vpc_attachment.TransitGatewayAttachmentSecVPC
  ]

  destination_cidr_block = "10.0.0.0/8"
  route_table_id         = aws_route_table.SecRouteTablePrivate.id
  transit_gateway_id     = aws_ec2_transit_gateway.TransitGateway.id
}

resource "aws_route" "PrivateRoute2" {
  depends_on = [
    aws_ec2_transit_gateway_vpc_attachment.TransitGatewayAttachmentSecVPC
  ]

  destination_cidr_block = "192.168.0.0/16"
  route_table_id         = aws_route_table.SecRouteTablePrivate.id
  transit_gateway_id     = aws_ec2_transit_gateway.TransitGateway.id
}

resource "aws_route" "PrivateRoute3" {
  depends_on = [
    aws_ec2_transit_gateway_vpc_attachment.TransitGatewayAttachmentSecVPC
  ]

  destination_cidr_block = "172.16.0.0/12"
  route_table_id         = aws_route_table.SecRouteTablePrivate.id
  transit_gateway_id     = aws_ec2_transit_gateway.TransitGateway.id
}

resource "aws_route" "PublicRoute1" {
  depends_on = [
    aws_ec2_transit_gateway_vpc_attachment.TransitGatewayAttachmentSecVPC
  ]

  destination_cidr_block = "0.0.0.0/0"
  route_table_id         = aws_route_table.SecRouteTablePublic.id
  gateway_id             = aws_internet_gateway.igw1.id
}

resource "aws_route" "ManagementRoute1" {
  depends_on = [
    aws_ec2_transit_gateway_vpc_attachment.TransitGatewayAttachmentSecVPC
  ]

  destination_cidr_block = "10.0.0.0/8"
  route_table_id         = aws_route_table.SecRouteTableManagement.id
  transit_gateway_id     = aws_ec2_transit_gateway.TransitGateway.id
}

resource "aws_route" "ManagementRoute2" {
  depends_on = [
    aws_ec2_transit_gateway_vpc_attachment.TransitGatewayAttachmentSecVPC
  ]

  destination_cidr_block = "192.168.0.0/16"
  route_table_id         = aws_route_table.SecRouteTableManagement.id
  transit_gateway_id     = aws_ec2_transit_gateway.TransitGateway.id
}

resource "aws_route" "ManagementRoute3" {
  depends_on = [
    aws_ec2_transit_gateway_vpc_attachment.TransitGatewayAttachmentSecVPC
  ]

  destination_cidr_block = "172.16.0.0/12"
  route_table_id         = aws_route_table.SecRouteTableManagement.id
  transit_gateway_id     = aws_ec2_transit_gateway.TransitGateway.id
}

resource "aws_route" "ManagementRoute4" {
  depends_on = [
    aws_ec2_transit_gateway_vpc_attachment.TransitGatewayAttachmentSecVPC
  ]

  destination_cidr_block = "0.0.0.0/0"
  route_table_id         = aws_route_table.SecRouteTableManagement.id
  gateway_id             = aws_internet_gateway.igw1.id
}


#--------------------------------------------------
# Return Output Values
#--------------------------------------------------

output "TGWID" {
  value       = aws_ec2_transit_gateway.TransitGateway.id
  description = "Transit Gateway ID"
}



