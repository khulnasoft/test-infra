terraform {
  backend "s3" {
    bucket         = "khulnasoft-distribution-state-bucket"
    dynamodb_table = "khulnasoft-distribution-state-bucket-lock"
    region         = "eu-west-1"
    key            = "terraform.tfstate"
  }
}
