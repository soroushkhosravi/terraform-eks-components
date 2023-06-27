variable "app_name" {
  description = "Name of ecr repository to push the nginx images to."
  type        = string
}

variable "needNginx"{
  description = "Do we need to create an nginx ecr repository."
  type        = bool
  default     = false
}

variable "cluster_url"{
  description = "The url of the EKS cluster."
  type        = string
}

variable "cluster_arn"{
  description = "The arn of the eks cluster."
  type        = string
}