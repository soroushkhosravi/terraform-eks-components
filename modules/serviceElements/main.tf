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

