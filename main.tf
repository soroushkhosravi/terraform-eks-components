# Provides required providers for the terraform.
terraform {
  required_providers {
    # It gets the credentials from env variables.
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16"
    }
    kubectl = {
      source  = "gavinbunney/kubectl"
      version = ">= 1.7.0"
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

provider "kubectl" {
  host                   = aws_eks_cluster.example.endpoint
  cluster_ca_certificate = base64decode(aws_eks_cluster.example.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.cluster-auth.token
}

provider "kubernetes" {
  host                   = aws_eks_cluster.example.endpoint
  cluster_ca_certificate = base64decode(aws_eks_cluster.example.certificate_authority[0].data)
  #exec {
  #api_version = "client.authentication.k8s.io/v1beta1"
  #args        = ["eks", "get-token", "--cluster-name", data.aws_eks_cluster.example.name]
  #command     = "aws"
  #}
  token = data.aws_eks_cluster_auth.cluster-auth.token
}

resource "kubernetes_namespace" "example" {
  metadata {
    annotations = {
      name = "housing-api"
    }

    name = "housing-api"
  }
}

data "aws_eks_cluster_auth" "cluster-auth" {
  name = aws_eks_cluster.example.name
}

provider "aws" {
  # We define the region of aws here.
  region = "us-west-2"
}

# We create all the VPC and subnets and route tables through this tech stack.
resource "aws_cloudformation_stack" "my-eks-vpc-stack" {
  name = "my-eks-vpc-stack"
  # The following template url adds private subnets, related route tables for them and
  # some NAT gateways which is expensive and not good for testing.
  # template_url = "https://s3.us-west-2.amazonaws.com/amazon-eks/cloudformation/2020-10-29/amazon-eks-vpc-private-subnets.yaml"
  template_body = file("${path.module}/stack.yml")
  on_failure    = "DELETE"
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
  subnet_ids      = slice(split(",", aws_cloudformation_stack.my-eks-vpc-stack.outputs.SubnetIds), 0, 2)

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
            format("%s:%s", replace(aws_iam_openid_connect_provider.cluster.url, "https://", ""), "sub") : "system:serviceaccount:housing-api:housing-api"
          }
        }
      }
    ]
  })
  tags = merge(
    {
      "ServiceAccountName"      = "aws-node"
      "ServiceAccountNameSpace" = "housing-api"
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

# This policy is created for the load balancer controller.
resource "aws_iam_policy" "AWSLoadBalancerControllerIAMPolicy" {
  policy = file("policies/load-balancer.json")
}

# We create an IAM role for the load balancer controller.
# We create an IAM role for the open ID connect.
resource "aws_iam_role" "AmazonEKSLoadBalancerControllerRole" {
  name = "AmazonEKSLoadBalancerControllerRole"
  assume_role_policy = jsonencode(
    {
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
              format("%s:%s", replace(aws_iam_openid_connect_provider.cluster.url, "https://", ""), "aud") : "sts.amazonaws.com",
              format("%s:%s", replace(aws_iam_openid_connect_provider.cluster.url, "https://", ""), "sub") : "system:serviceaccount:kube-system:aws-load-balancer-controller"
            }
          }
        }
      ]
    }
  )
  depends_on = [aws_iam_openid_connect_provider.cluster]
}

resource "aws_iam_role_policy_attachment" "AmazonEKSLoadBalancerControllerRoleAttachement" {
  role       = aws_iam_role.AmazonEKSLoadBalancerControllerRole.name
  policy_arn = aws_iam_policy.AWSLoadBalancerControllerIAMPolicy.arn
  depends_on = [
    aws_iam_role.AmazonEKSLoadBalancerControllerRole
  ]
}


resource "kubectl_manifest" "test" {
  yaml_body = file("${path.module}/kubectls/aws-load-balancer-controller-service-account.yaml")
}

# For being able to have "AWS Load balancer controller" in your cluster, do the steps of 5 and 6 of the following link:
# https://docs.aws.amazon.com/eks/latest/userguide/aws-load-balancer-controller.html
# In fact, you can do the following steps after running terraform apply and haing the EKS cluster ready.
# 1. Updating EKS configuration for having access to the cluster by the following commmand:
# aws eks update-kubeconfig --name my-cluster --region us-west-2
# 2. Run the following command to install cert manager in the cluster:
# kubectl apply --validate=false -f https://github.com/jetstack/cert-manager/releases/download/v1.5.4/cert-manager.yaml
# 3. Run the following coomand:
# kubectl apply -f kubectls/v2_4_4_full.yaml
# 4. Runnning the following command:
# kubectl apply -f kubectls/v2_4_4_ingclass.yaml
# 5. Run the following command to make sure the load balancer controller is installed properly:
# kubectl get deployment -n kube-system aws-load-balancer-controller


