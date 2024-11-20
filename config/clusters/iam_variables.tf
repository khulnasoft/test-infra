variable "state_dynamodb_table_name" {
  type        = string
  description = "The name of the DynamoDB table for the Terraform state"
  default     = "khulnasoft-test-infra-state-lock"
}
