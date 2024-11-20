variable "bucket_name" {
  type    = string
  default = "khulnasoft-distribution"
}

variable "logging_bucket_name" {
  type    = string
  default = "logging-khulnasoft-distribution"
}

variable "region" {
  type    = string
  default = "eu-west-1"
}

variable "distribution_origin_id" {
  type    = string
  default = "khulnasoftDistributionOrigin"
}

variable "distribution_name_alias" {
  type    = string
  default = "download.khulnasoft.com"
}

variable "playground_bucket_name" {
  type = string
  default = "khulnasoft-playground"
}

variable "playground_name_alias" {
  type = string
  default = "play.khulnasoft.com"
}

variable "playground_origin_id" {
  type = string
  default = "khulnasoftPlaygroundOrigin"
}