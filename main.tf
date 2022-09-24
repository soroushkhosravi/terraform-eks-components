# Provides required providers for the terraform.
terraform {
  required_providers {
    # It gets the credentials from env variables.
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.4"
    }
  }
  # We define a backend for the terraform state file. This saves all the changes related to the AWS elements.
  backend "s3" {
    bucket = "infrastructure-my-cluster"
    key    = "statefile"
    region = "us-west-2"
  }
  required_version = ">= 1.2.0"
}

provider "aws" {
  # We define the region of aws here.
  region = "us-west-2"
}

provider "kubernetes" {
  # We define which cluster we want to connect to.
  host                   = aws_eks_cluster.example.endpoint
  cluster_ca_certificate = base64decode(aws_eks_cluster.example.certificate_authority[0].data)
  exec {
    api_version = "client.authentication.k8s.io/v1alpha1"
    args        = ["eks", "get-token", "--cluster-name", aws_eks_cluster.example.name]
    command     = "aws"
  }
}

# We create all the VPC and subnets and route tables through this tech stack.
resource "aws_cloudformation_stack" "my-eks-vpc-stack" {
  name         = "my-eks-vpc-stack"
  template_url = "https://s3.us-west-2.amazonaws.com/amazon-eks/cloudformation/2020-10-29/amazon-eks-vpc-private-subnets.yaml"
  on_failure   = "DELETE"
}

# We define an IAM role for our EKS cluster.
resource "aws_iam_role" "myAmazonEKSClusterRole" {
  name = "myAmazonEKSClusterRole"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Service" : "eks.amazonaws.com"
        },
        "Action" : "sts:AssumeRole"
      }
    ]
  })
}

# We assign a policy to the cluster's role.
resource "aws_iam_role_policy_attachment" "eks-policy-attachment" {
  role       = aws_iam_role.myAmazonEKSClusterRole.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  depends_on = [
    aws_iam_role.myAmazonEKSClusterRole
  ]
}

# We create an EKS cluster here.
resource "aws_eks_cluster" "example" {
  name     = "my-cluster"
  role_arn = aws_iam_role.myAmazonEKSClusterRole.arn

  vpc_config {
    subnet_ids = split(",", aws_cloudformation_stack.my-eks-vpc-stack.outputs.SubnetIds)
  }
  # Ensure that IAM Role permissions are created before and deleted after EKS Cluster handling.
  # Otherwise, EKS will not be able to properly delete EKS managed EC2 infrastructure such as Security Groups.
  depends_on = [
    aws_iam_role_policy_attachment.eks-policy-attachment,
  ]
}

# We define an IAM roles for all the nodes in the cluster.
resource "aws_iam_role" "myAmazonEKSNodeRole" {
  name = "myAmazonEKSNodeRole"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Service" : "ec2.amazonaws.com"
        },
        "Action" : "sts:AssumeRole"
      }
    ]
  })
}


resource "aws_iam_role_policy_attachment" "eks-node-policy-attachment-1" {
  role       = aws_iam_role.myAmazonEKSNodeRole.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  depends_on = [
    aws_iam_role.myAmazonEKSNodeRole
  ]
}

resource "aws_iam_role_policy_attachment" "eks-node-policy-attachment-2" {
  role       = aws_iam_role.myAmazonEKSNodeRole.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  depends_on = [
    aws_iam_role.myAmazonEKSNodeRole
  ]
}

resource "aws_iam_role_policy_attachment" "eks-node-policy-attachment-3" {
  role       = aws_iam_role.myAmazonEKSNodeRole.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  depends_on = [
    aws_iam_role.myAmazonEKSNodeRole
  ]
}

# We define a node group for our Nodes. We assign the IAM ole to it.
resource "aws_eks_node_group" "my-nodegroup" {
  cluster_name    = aws_eks_cluster.example.name
  node_group_name = "my-nodegroup"
  node_role_arn   = aws_iam_role.myAmazonEKSNodeRole.arn
  subnet_ids      = split(",", aws_cloudformation_stack.my-eks-vpc-stack.outputs.SubnetIds)

  scaling_config {
    desired_size = 2
    max_size     = 2
    min_size     = 2
  }

  update_config {
    max_unavailable = 1
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
  # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
  depends_on = [
    aws_iam_role_policy_attachment.eks-node-policy-attachment-1,
    aws_iam_role_policy_attachment.eks-node-policy-attachment-2,
    aws_iam_role_policy_attachment.eks-node-policy-attachment-3,
  ]
}

# We create a tls certificate for the cluster.
data "tls_certificate" "cluster" {
  url = aws_eks_cluster.example.identity.0.oidc.0.issuer
}

# We create an AWS IAM connect provider enabling us to use service account.
resource "aws_iam_openid_connect_provider" "cluster" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = concat([data.tls_certificate.cluster.certificates.0.sha1_fingerprint])
  url             = aws_eks_cluster.example.identity.0.oidc.0.issuer
}

# We create an IAM role for the open ID connect.
resource "aws_iam_role" "aws_node" {
  name = "aws-node"
  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Federated" : aws_iam_openid_connect_provider.cluster.arn
        },
        "Action" : "sts:AssumeRoleWithWebIdentity",
        "Condition" : {
          "StringEquals" : {
            format("%s:%s", replace(aws_iam_openid_connect_provider.cluster.url, "https://", ""), "sub") : "system:serviceaccount:default:housing-api"
          }
        }
      }
    ]
  })
  tags = merge(
    {
      "ServiceAccountName"      = "aws-node"
      "ServiceAccountNameSpace" = "default"
    }
  )
  inline_policy {
    name = "ssm_full_access_policy"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action   = ["ssm:*"]
          Effect   = "Allow"
          Resource = "*"
        },
      ]
    })
  }
  depends_on = [aws_iam_openid_connect_provider.cluster]
}
resource "aws_iam_role_policy_attachment" "aws_node" {
  role       = aws_iam_role.aws_node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  depends_on = [aws_iam_role.aws_node]
}