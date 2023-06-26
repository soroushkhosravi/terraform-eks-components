variable "app_ecr_repository_name" {
  description = "Name of ecr repository to push the nginx images to."
  type        = string
}

variable "needNginx"{
  description = "Do we need to create an nginx ecr repository."
  type        = bool
  default     = false
}