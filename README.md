# required components for EKS through terraform.

This repository gives you all the required components to have an EKS cluster and being able to connect to it.

# Explanations

In order to be able to use this repository, you need to have the following ENV variables in your system that enables
you to connect to AWS. 

The related IAM user should have the all the possible roles and should be kind of admin:
```
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
```

In terms of the related `region` for the `AWS`, you can set it up through the following ENV varibale or you can pass it 
to the `provider "aws"` block ain the `main.tf` file.

For more information on how to set up `AWS` provider, read the following link:

https://registry.terraform.io/providers/hashicorp/aws/latest/docs

# How to create required components

In order to create the required components in `AWS`, you can run the following commands in the root of the repository.

```
terraform fmt
terraform init
terraform plan
terraform apply
```

# Replacing the variables in the file

1. In order to define a new name for your cluster, change the `my-cluster` to the name you want for your cluster.
2. In order to be able to save your `tf state file`, you should have a bucket named `infrastructure-my-cluster` in the related `aws region`.
3. If you want to also create the bucket through terraform, follow the following url.
https://dev.to/shihanng/managing-s3-bucket-for-terraform-backend-in-the-same-configuration-2c6c
4. In order to be able to have a service account for your deployments, look at the `aws_node` IAM role. The service account
name is `housing-api` for the `default` cluster.


