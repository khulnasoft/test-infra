resource "aws_s3_bucket" "khulnasoft-test-infra-state" {
  bucket = "khulnasoft-test-infra-state"

  policy = null

  lifecycle {
    prevent_destroy = false
  }

  tags = module.label.tags
}

resource "aws_s3_bucket_versioning" "khulnasoft-test-infra-state_versioning" {
  bucket = aws_s3_bucket.khulnasoft-test-infra-state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "khulnasoft-test-infra-state_server_side_encryption_configuration" {
  bucket = aws_s3_bucket.khulnasoft-test-infra-state.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.khulnasoft-test-infra-state.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_acl" "khulnasoft-test-infra-state_acl" {
  bucket = aws_s3_bucket.khulnasoft-test-infra-state.id
  acl    = "private"
}

resource "aws_kms_key" "khulnasoft-test-infra-state" {
  description             = "Khulnasoft Test Infra state master encryption key"
  deletion_window_in_days = 10
  enable_key_rotation     = true
}

resource "aws_dynamodb_table" "khulnasoft-test-infra-state-lock" {
  name           = "khulnasoft-test-infra-state-lock"
  hash_key       = "LockID"
  read_capacity  = 20
  write_capacity = 20

  attribute {
    name = "LockID"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }
}


resource "aws_s3_bucket_policy" "khulnasoft-test-infra-state" {
  bucket = aws_s3_bucket.khulnasoft-test-infra-state.id
  policy = data.aws_iam_policy_document.khulnasoft-test-infra-state.json
}

data "aws_iam_policy_document" "khulnasoft-test-infra-state" {
  statement {
    sid    = "AllowAllTestInfraUsersAccessToTestInfraState"
    effect = "Allow"

    actions = [
      "s3:*",
    ]

    resources = [
      aws_s3_bucket.khulnasoft-test-infra-state.arn,
      "${aws_s3_bucket.khulnasoft-test-infra-state.arn}/*",
    ]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

