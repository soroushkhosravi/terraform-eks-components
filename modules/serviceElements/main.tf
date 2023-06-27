# Creates a ECR repository for the housing api project to save the nginx images.
resource "aws_ecr_repository" "nginx-ecr-repository" {
  count                = var.needNginx ? 1 : 0
  name                 = format("%s-nginx", var.app_name)
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }
}

# Creates a ECR repository for the housing api project to save gunicorn images.
resource "aws_ecr_repository" "app-ecr-repository" {
  name                 = var.app_name
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }
}

# Create a namespace in our kubernetes cluster.
# How does this realise which cluster to create the namespace in it?
# It realises it from the kubernetes provider that we have provided.
resource "kubernetes_namespace" "example" {
  metadata {
    annotations = {
      name = var.app_name
    }

    name = var.app_name
  }
}

resource "aws_iam_role" "aws_node" {
  name = var.app_name
  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Federated" : var.cluster_arn
        },
        "Action" : "sts:AssumeRoleWithWebIdentity",
        "Condition" : {
          "StringEquals" : {
            format("%s:%s", replace(var.cluster_url, "https://", ""), "sub") : format("system:serviceaccount:%s:%s", var.app_name, var.app_name)
          }
        }
      }
    ]
  })
  tags = merge(
    {
      "ServiceAccountName"      = var.app_name
      "ServiceAccountNameSpace" = var.app_name
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
}

resource "aws_iam_role_policy_attachment" "aws_node" {
  role       = aws_iam_role.aws_node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  depends_on = [aws_iam_role.aws_node]
}
