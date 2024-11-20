resource "aws_acm_certificate" "monitor_prow" {
  domain_name       = "monitoring.prow.khulnasoft.com"
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

