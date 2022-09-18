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


