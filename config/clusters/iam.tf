data "aws_canonical_user_id" "current_user" {}

data "aws_caller_identity" "current" {}

##### EBS CSI controller

module "ebs_csi_controller" {
  source           = "terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"
  version          = "4.1.0"
  create_role      = true
  role_name        = "${local.cluster_name}-ebs-csi-controller"
  provider_url     = replace(module.eks.cluster_oidc_issuer_url, "https://", "")
  role_policy_arns = [aws_iam_policy.ebs_controller_policy.arn]
  oidc_fully_qualified_subjects = [
    "system:serviceaccount:kube-system:ebs-csi-controller-sa",
  ]
}

resource "aws_iam_policy" "ebs_controller_policy" {
  name_prefix = "${local.cluster_name}-ebs-csi-driver"
  policy      = data.aws_iam_policy_document.ebs_controller_policy_doc.json
}

data "aws_iam_policy_document" "ebs_controller_policy_doc" {
  statement {
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "ec2:CreateSnapshot",
      "ec2:AttachVolume",
      "ec2:DetachVolume",
      "ec2:ModifyVolume",
      "ec2:DescribeAvailabilityZones",
      "ec2:DescribeInstances",
      "ec2:DescribeSnapshots",
      "ec2:DescribeTags",
      "ec2:DescribeVolumes",
      "ec2:DescribeVolumesModifications",
    ]
  }

  statement {
    effect = "Allow"

    resources = [
      "arn:aws:ec2:*:*:volume/*",
      "arn:aws:ec2:*:*:snapshot/*",
    ]

    actions = ["ec2:CreateTags"]
  }

  statement {
    effect = "Allow"

    resources = [
      "arn:aws:ec2:*:*:volume/*",
      "arn:aws:ec2:*:*:snapshot/*",
    ]

    actions = ["ec2:DeleteTags"]
  }

  statement {
    effect    = "Allow"
    resources = ["*"]
    actions   = ["ec2:CreateVolume"]

    condition {
      test     = "StringLike"
      variable = "aws:RequestTag/ebs.csi.aws.com/cluster"
      values   = ["true"]
    }
  }

  statement {
    effect    = "Allow"
    resources = ["*"]
    actions   = ["ec2:CreateVolume"]

    condition {
      test     = "StringLike"
      variable = "aws:RequestTag/CSIVolumeName"
      values   = ["*"]
    }
  }

  statement {
    effect    = "Allow"
    resources = ["*"]
    actions   = ["ec2:DeleteVolume"]

    condition {
      test     = "StringLike"
      variable = "ec2:ResourceTag/ebs.csi.aws.com/cluster"
      values   = ["true"]
    }
  }

  statement {
    effect    = "Allow"
    resources = ["*"]
    actions   = ["ec2:DeleteVolume"]

    condition {
      test     = "StringLike"
      variable = "ec2:ResourceTag/CSIVolumeName"
      values   = ["*"]
    }
  }

  statement {
    effect    = "Allow"
    resources = ["*"]
    actions   = ["ec2:DeleteVolume"]

    condition {
      test     = "StringLike"
      variable = "ec2:ResourceTag/kubernetes.io/created-for/pvc/name"
      values   = ["*"]
    }
  }

  statement {
    effect    = "Allow"
    resources = ["*"]
    actions   = ["ec2:DeleteSnapshot"]

    condition {
      test     = "StringLike"
      variable = "ec2:ResourceTag/CSIVolumeSnapshotName"
      values   = ["*"]
    }
  }

  statement {
    effect    = "Allow"
    resources = ["*"]
    actions   = ["ec2:DeleteSnapshot"]

    condition {
      test     = "StringLike"
      variable = "ec2:ResourceTag/ebs.csi.aws.com/cluster"
      values   = ["true"]
    }
  }
}

##### Cluster-autoscaler

module "cluster_autoscaler" {
  source           = "terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"
  version          = "4.1.0"
  create_role      = true
  role_name        = "${local.cluster_name}-cluster-autoscaler"
  provider_url     = replace(module.eks.cluster_oidc_issuer_url, "https://", "")
  role_policy_arns = [aws_iam_policy.cluster_autoscaler_policy.arn]
  oidc_fully_qualified_subjects = [
    "system:serviceaccount:kube-system:cluster-autoscaler",
  ]
}

resource "aws_iam_policy" "cluster_autoscaler_policy" {
  name_prefix = "${local.cluster_name}-cluster-autoscaler"
  policy      = data.aws_iam_policy_document.cluster_autoscaler_policy_doc.json
}

data "aws_iam_policy_document" "cluster_autoscaler_policy_doc" {
  statement {
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "autoscaling:DescribeAutoScalingGroups",
      "autoscaling:DescribeAutoScalingInstances",
      "autoscaling:DescribeLaunchConfigurations",
      "autoscaling:DescribeScalingActivities",
      "ec2:DescribeImages",
      "ec2:DescribeInstanceTypes",
      "ec2:DescribeLaunchTemplateVersions",
      "ec2:GetInstanceTypesFromInstanceRequirements",
      "eks:DescribeNodegroup",
    ]
  }

  statement {
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "autoscaling:SetDesiredCapacity",
      "autoscaling:TerminateInstanceInAutoScalingGroup",
    ]
  }
}

##### S3 for Prow uploads

module "iam_assumable_role_admin" {
  source           = "terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"
  version          = "4.1.0"
  create_role      = true
  role_name        = "${local.cluster_name}-prow_s3_access"
  provider_url     = replace(module.eks.cluster_oidc_issuer_url, "https://", "")
  role_policy_arns = [aws_iam_policy.s3_access.arn]
  oidc_fully_qualified_subjects = [
    "system:serviceaccount:${local.k8s_service_account_namespace}:tide",
    "system:serviceaccount:${local.k8s_service_account_namespace}:deck",
    "system:serviceaccount:${local.k8s_service_account_namespace}:crier",
    "system:serviceaccount:${local.k8s_service_account_namespace}:statusreconciler",
    "system:serviceaccount:${local.k8s_service_account_namespace}:prow-controller-manager"
  ]
}

resource "aws_iam_policy" "s3_access" {
  name_prefix = "${local.cluster_name}-prow-s3"
  description = "EKS s3 access policy for cluster ${module.eks.cluster_id}"
  policy      = data.aws_iam_policy_document.s3_access.json
}

data "aws_iam_policy_document" "s3_access" {
  statement {
    sid    = "prows3access"
    effect = "Allow"

    actions = [
      "s3:*",
    ]

    resources = [
      aws_s3_bucket.prow_storage.arn,
      "arn:aws:s3:::*/*",
    ]
  }

  statement {
    sid = "AllowToEncryptDecryptS3Bucket"

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:GenerateDataKey",
    ]
    resources = [
      aws_kms_key.prow_storage.arn,
    ]
  }
}

##### S3 for Prow uploads

module "driver_kit_s3_role" {
  source           = "terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"
  version          = "4.1.0"
  create_role      = true
  role_name        = "${local.cluster_name}-drivers_s3_access"
  provider_url     = replace(module.eks.cluster_oidc_issuer_url, "https://", "")
  role_policy_arns = [aws_iam_policy.driverkit_s3_access.arn]
  oidc_fully_qualified_subjects = [
    "system:serviceaccount:${local.k8s_test_service_account_namespace}:driver-kit",
  ]
}

resource "aws_iam_policy" "driverkit_s3_access" {
  name_prefix = "${local.cluster_name}-driverkit-s3"
  description = "EKS s3 access policy for cluster ${module.eks.cluster_id}"
  policy      = data.aws_iam_policy_document.driverkit_s3_access.json
}

data "aws_iam_policy_document" "driverkit_s3_access" {
  statement {
    sid    = "driverkits3access"
    effect = "Allow"
    actions = [
      "s3:*"
    ]
    resources = [
      "arn:aws:s3:::khulnasoft-distribution/driver/*",
      "arn:aws:s3:::khulnasoft-distribution/driver",
    ]
  }
}

##### Permissions for GitHub Actions

# GHA OIDC Provider, required to integrate with any GHA workflow
module "iam_github_oidc_provider" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-github-oidc-provider"
  version = "5.10.0"
}

# Rules repository

module "rules_s3_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-github-oidc-role"
  version = "5.10.0"
  create  = true
  subjects = [
    "khulnasoft/rules:ref:refs/heads/main",
    "khulnasoft/rules:ref:refs/tags/*"
  ]
  policies = {
    rules_s3_access = "${aws_iam_policy.rules_s3_access.arn}"
  }
}

resource "aws_iam_policy" "rules_s3_access" {
  name_prefix = "github_actions-rules-s3"
  description = "GitHub actions S3 access policy for rules"
  policy      = data.aws_iam_policy_document.rules_s3_access.json
}

data "aws_iam_policy_document" "rules_s3_access" {
  statement {
    sid    = "UploadRulesS3Access"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObjectAcl",
      "s3:GetObject",
      "s3:DeleteObject",
      "s3:PutObjectAcl"
    ]
    resources = [
      "arn:aws:s3:::khulnasoft-distribution/rules/*",
      "arn:aws:s3:::khulnasoft-distribution/rules",
    ]
  }
}

# Plugins repository

module "plugins_s3_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-github-oidc-role"
  version = "5.10.0"
  name    = "github_actions-plugins-s3"
  create  = true
  subjects = [
    "khulnasoft/plugins:ref:refs/heads/main",
    "khulnasoft/plugins:ref:refs/tags/*"
  ]
  policies = {
    plugins_s3_access = "${aws_iam_policy.plugins_s3_access.arn}"
  }
}

resource "aws_iam_policy" "plugins_s3_access" {
  name_prefix = "github_actions-plugins-s3"
  description = "GitHub actions S3 access policy for plugins repo workflows"
  policy      = data.aws_iam_policy_document.plugins_s3_access.json
}

data "aws_iam_policy_document" "plugins_s3_access" {
  statement {
    sid    = "UploadPluginsS3Access"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObjectAcl",
      "s3:GetObject",
      "s3:DeleteObject",
      "s3:PutObjectAcl"
    ]
    resources = [
      "arn:aws:s3:::khulnasoft-distribution/plugins/*",
      "arn:aws:s3:::khulnasoft-distribution/plugins/",
    ]
  }
}

# Test-infra repository

module "test-infra_cluster_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-github-oidc-role"
  version = "5.10.0"
  name    = "github_actions-test-infra-cluster"
  create  = true
  subjects = [
    "khulnasoft/test-infra:ref:refs/heads/master"
  ]
  policies = {
    test-infra_cluster_access = "${aws_iam_policy.test-infra_cluster_access.arn}"
  }
}

resource "aws_iam_policy" "test-infra_cluster_access" {
  name_prefix = "github_actions-test-infra-cluster"
  description = "GitHub actions cluster access policy for test-infra master terraform/prow deploy"
  policy      = data.aws_iam_policy_document.test-infra_cluster_access.json
}

data "aws_iam_policy_document" "test-infra_cluster_access" {
  statement {
    sid    = "DeployTestInfraClusterAccess"
    effect = "Allow"
    actions = [
      "*"
    ]
    resources = [
      "*"
    ]
  }
}

module "test-infra_reader" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-github-oidc-role"
  version = "5.10.0"
  name    = "github_actions-test-infra-reader"
  create  = true
  subjects = [
    "khulnasoft/test-infra:pull_request"
  ]
  policies = {
    test-infra_read_access = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    test-infra_state_lock  = "${aws_iam_policy.test-infra_state_lock.arn}"
  }
}

resource "aws_iam_policy" "test-infra_state_lock" {
  name_prefix = "github_actions-test-infra-cluster"
  description = "Access policy for test-infra Terraform remote state lock"
  policy      = data.aws_iam_policy_document.test-infra_state_lock.json
}

data "aws_iam_policy_document" "test-infra_state_lock" {
  statement {
    sid    = "DeployTestInfraClusterAccess"
    effect = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:DeleteItem"
    ]
    resources = [
      "arn:aws:dynamodb:::table/${var.state_dynamodb_table_name}"
    ]
  }
}

module "test-infra_s3_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-github-oidc-role"
  version = "5.10.0"
  name    = "github_actions-test-infra-s3"
  create  = true
  subjects = [
    "khulnasoft/test-infra:ref:refs/heads/master"
  ]
  policies = {
    test-infra_s3_access = "${aws_iam_policy.test-infra_s3_access.arn}"
  }
}

resource "aws_iam_policy" "test-infra_s3_access" {
  name_prefix = "github_actions-test-infra-s3"
  description = "GitHub actions S3 access policy for test-infra update-drivers-website workflow"
  policy      = data.aws_iam_policy_document.test-infra_s3_access.json
}

data "aws_iam_policy_document" "test-infra_s3_access" {
  statement {
    sid    = "UploadTestInfraS3Access"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObjectAcl",
      "s3:GetObject",
      "s3:DeleteObject",
      "s3:PutObjectAcl"
    ]
    resources = [
      "arn:aws:s3:::khulnasoft-distribution/driver/site/*",
      "arn:aws:s3:::khulnasoft-distribution/driver/site",
    ]
  }
}

# Khulnasoft repository (dev packages)

module "khulnasoft_dev_s3_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-github-oidc-role"
  version = "5.10.0"
  name    = "github_actions-khulnasoft-dev-s3"
  create  = true
  subjects = [
    "khulnasoft/khulnasoft:ref:refs/heads/master",
    "khulnasoft/khulnasoft:ref:refs/tags/*"
  ]
  policies = {
    khulnasoft_s3_access = "${aws_iam_policy.khulnasoft_dev_s3_access.arn}"
  }
}

resource "aws_iam_policy" "khulnasoft_dev_s3_access" {
  name_prefix = "github_actions-khulnasoft-dev-s3"
  description = "GitHub actions S3 access policy for khulnasoft repo dev workflows"
  policy      = data.aws_iam_policy_document.khulnasoft_dev_s3_access.json
}

data "aws_iam_policy_document" "khulnasoft_dev_s3_access" {
  statement {
    sid    = "UploadKhulnasoftDevS3Access"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObjectAcl",
      "s3:GetObject",
      "s3:DeleteObject",
      "s3:PutObjectAcl"
    ]
    resources = [
      "arn:aws:s3:::khulnasoft-distribution/packages/*-dev/*",
      "arn:aws:s3:::khulnasoft-distribution/packages/*-dev/",
    ]
  }
  statement {
    sid    = "BuildKhulnasoftDevCloudFrontAccess"
    effect = "Allow"
    actions = [
      "cloudfront:CreateInvalidation"
    ]
    resources = [
      "arn:aws:cloudfront::292999226676:distribution/E1CQNPFWRXLGQD"
    ]
  }
}

# Khulnasoft repository (releases)

module "khulnasoft_s3_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-github-oidc-role"
  version = "5.10.0"
  name    = "github_actions-khulnasoft-s3"
  create  = true
  subjects = [
    "khulnasoft/khulnasoft:ref:refs/tags/*"
  ]
  policies = {
    khulnasoft_s3_access = "${aws_iam_policy.khulnasoft_s3_access.arn}"
  }
}

resource "aws_iam_policy" "khulnasoft_s3_access" {
  name_prefix = "github_actions-khulnasoft-s3"
  description = "GitHub actions S3 access policy for khulnasoft repo workflows"
  policy      = data.aws_iam_policy_document.khulnasoft_s3_access.json
}

data "aws_iam_policy_document" "khulnasoft_s3_access" {
  statement {
    sid    = "UploadKhulnasoftS3Access"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObjectAcl",
      "s3:GetObject",
      "s3:DeleteObject",
      "s3:PutObjectAcl"
    ]
    resources = [
      "arn:aws:s3:::khulnasoft-distribution/packages/*",
      "arn:aws:s3:::khulnasoft-distribution/packages/",
    ]
  }
  statement {
    sid    = "BuildKhulnasoftCloudFrontAccess"
    effect = "Allow"
    actions = [
      "cloudfront:CreateInvalidation"
    ]
    resources = [
      "arn:aws:cloudfront::292999226676:distribution/E1CQNPFWRXLGQD"
    ]
  }
}

# Khulnasoft repository (ECR)

module "khulnasoft_ecr_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-github-oidc-role"
  name    = "github_actions-khulnasoft-ecr"
  version = "5.10.0"
  create  = true
  subjects = [
    "khulnasoft/khulnasoft:ref:refs/heads/master",
    "khulnasoft/khulnasoft:ref:refs/tags/*"
  ]
  policies = {
    khulnasoft_ecr_access = "${aws_iam_policy.khulnasoft_ecr_access.arn}"
  }
}

resource "aws_iam_policy" "khulnasoft_ecr_access" {
  name_prefix = "github_actions-khulnasoft-ecr"
  description = "GitHub actions ECR access policy for khulnasoft"
  policy      = data.aws_iam_policy_document.khulnasoft_ecr_access.json
}

data "aws_iam_policy_document" "khulnasoft_ecr_access" {
  statement {
    sid    = "BuildKhulnasoftECRAccess"
    effect = "Allow"
    actions = [
      "ecr-public:BatchCheckLayerAvailability",
      "ecr-public:GetRepositoryPolicy",
      "ecr-public:DescribeRepositories",
      "ecr-public:DescribeImages",
      "ecr-public:InitiateLayerUpload",
      "ecr-public:UploadLayerPart",
      "ecr-public:CompleteLayerUpload",
      "ecr-public:PutImage"
    ]
    resources = [
      "arn:aws:ecr-public::292999226676:repository/khulnasoft",
      "arn:aws:ecr-public::292999226676:repository/khulnasoft-driver-loader",
      "arn:aws:ecr-public::292999226676:repository/khulnasoft-no-driver",
      "arn:aws:ecr-public::292999226676:repository/khulnasoft-driver-loader-legacy",
      "arn:aws:ecr-public::292999226676:repository/khulnasoft-distroless"
    ]
  }
  statement {
    sid    = "BuildKhulnasoftECRTokenAccess"
    effect = "Allow"
    actions = [
      "ecr-public:GetAuthorizationToken",
      "sts:GetServiceBearerToken"
    ]
    resources = ["*"]
  }
}

# Diginfra repository

module "diginfra_ecr_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-github-oidc-role"
  name    = "github_actions-diginfra-ecr"
  version = "5.10.0"
  create  = true
  subjects = [
    "khulnasoft/diginfra:ref:refs/heads/master",
    "khulnasoft/diginfra:ref:refs/tags/*"
  ]
  policies = {
    diginfra_ecr_access = "${aws_iam_policy.diginfra_ecr_access.arn}"
  }
}

resource "aws_iam_policy" "diginfra_ecr_access" {
  name_prefix = "github_actions-diginfra-ecr"
  description = "GitHub actions ECR access policy for diginfra"
  policy      = data.aws_iam_policy_document.diginfra_ecr_access.json
}

data "aws_iam_policy_document" "diginfra_ecr_access" {
  statement {
    sid    = "BuildDiginfraECRAccess"
    effect = "Allow"
    actions = [
      "ecr-public:BatchCheckLayerAvailability",
      "ecr-public:GetRepositoryPolicy",
      "ecr-public:DescribeRepositories",
      "ecr-public:DescribeImages",
      "ecr-public:InitiateLayerUpload",
      "ecr-public:UploadLayerPart",
      "ecr-public:CompleteLayerUpload",
      "ecr-public:PutImage"
    ]
    resources = [
      "arn:aws:ecr-public::292999226676:repository/diginfra"
    ]
  }
  statement {
    sid    = "BuildDiginfraECRTokenAccess"
    effect = "Allow"
    actions = [
      "ecr-public:GetAuthorizationToken",
      "sts:GetServiceBearerToken"
    ]
    resources = ["*"]
  }
}

# Diginfra-UI repository

module "diginfra_ui_ecr_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-github-oidc-role"
  name    = "github_actions-diginfra-ui-ecr"
  version = "5.10.0"
  create  = true
  subjects = [
    "khulnasoft/diginfra-ui:ref:refs/heads/master",
    "khulnasoft/diginfra-ui:ref:refs/tags/*"
  ]
  policies = {
    diginfra_ui_ecr_access = "${aws_iam_policy.diginfra_ui_ecr_access.arn}"
  }
}

resource "aws_iam_policy" "diginfra_ui_ecr_access" {
  name_prefix = "github_actions-diginfra-ui-ecr"
  description = "GitHub actions ECR access policy for diginfra-ui"
  policy      = data.aws_iam_policy_document.diginfra_ui_ecr_access.json
}

data "aws_iam_policy_document" "diginfra_ui_ecr_access" {
  statement {
    sid    = "BuildDiginfraUIECRAccess"
    effect = "Allow"
    actions = [
      "ecr-public:BatchCheckLayerAvailability",
      "ecr-public:GetRepositoryPolicy",
      "ecr-public:DescribeRepositories",
      "ecr-public:DescribeImages",
      "ecr-public:InitiateLayerUpload",
      "ecr-public:UploadLayerPart",
      "ecr-public:CompleteLayerUpload",
      "ecr-public:PutImage"
    ]
    resources = [
      "arn:aws:ecr-public::292999226676:repository/diginfra-ui"
    ]
  }
  statement {
    sid    = "BuildDiginfraUIECRTokenAccess"
    effect = "Allow"
    actions = [
      "ecr-public:GetAuthorizationToken",
      "sts:GetServiceBearerToken"
    ]
    resources = ["*"]
  }
}

# Khulnasoftctl repository

module "khulnasoftctl_ecr_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-github-oidc-role"
  name    = "github_actions-khulnasoftctl-ecr"
  version = "5.10.0"
  create  = true
  subjects = [
    "khulnasoft/khulnasoftctl:ref:refs/heads/main",
    "khulnasoft/khulnasoftctl:ref:refs/tags/*"
  ]
  policies = {
    khulnasoftctl_ecr_access = "${aws_iam_policy.khulnasoftctl_ecr_access.arn}"
  }
}

resource "aws_iam_policy" "khulnasoftctl_ecr_access" {
  name_prefix = "github_actions-khulnasoftctl-ecr"
  description = "GitHub actions ECR access policy for khulnasoftctl"
  policy      = data.aws_iam_policy_document.khulnasoftctl_ecr_access.json
}

data "aws_iam_policy_document" "khulnasoftctl_ecr_access" {
  statement {
    sid    = "BuildKhulnasoftctlECRAccess"
    effect = "Allow"
    actions = [
      "ecr-public:BatchCheckLayerAvailability",
      "ecr-public:GetRepositoryPolicy",
      "ecr-public:DescribeRepositories",
      "ecr-public:DescribeImages",
      "ecr-public:InitiateLayerUpload",
      "ecr-public:UploadLayerPart",
      "ecr-public:CompleteLayerUpload",
      "ecr-public:PutImage"
    ]
    resources = [
      "arn:aws:ecr-public::292999226676:repository/khulnasoftctl"
    ]
  }
  statement {
    sid    = "BuildKhulnasoftctlECRTokenAccess"
    effect = "Allow"
    actions = [
      "ecr-public:GetAuthorizationToken",
      "sts:GetServiceBearerToken"
    ]
    resources = ["*"]
  }
}

# khulnasoft-playground repository

module "khulnasoft_playground_s3_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-github-oidc-role"
  version = "5.10.0"
  name    = "github_actions-khulnasoft-playground-s3"
  create  = true
  subjects = [
    "khulnasoft/khulnasoft-playground:ref:refs/tags/*"
  ]
  policies = {
    khulnasoft_playground_s3_access = "${aws_iam_policy.khulnasoft_playground_s3_access.arn}"
  }
}

resource "aws_iam_policy" "khulnasoft_playground_s3_access" {
  name_prefix = "github_actions-khulnasoft-playground-s3"
  description = "GitHub actions S3 access policy for khulnasoft-playground repo workflows"
  policy      = data.aws_iam_policy_document.khulnasoft_playground_s3_access.json
}

data "aws_iam_policy_document" "khulnasoft_playground_s3_access" {
  statement {
    sid    = "UploadKhulnasoftPlaygroundS3ContentAccess"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObjectAcl",
      "s3:GetObject",
      "s3:DeleteObject",
      "s3:PutObjectAcl"
    ]
    resources = [
      "arn:aws:s3:::khulnasoft-playground/*",
      "arn:aws:s3:::khulnasoft-playground/",
    ]
  }
  statement {
    sid    = "UploadKhulnasoftPlaygroundS3BucketAccess"
    effect = "Allow"
    actions = [
      "s3:ListBucket"
    ]
    resources = [
      "arn:aws:s3:::khulnasoft-playground",
    ]
  }
  statement {
    sid    = "BuildKhulnasoftPlaygroundCloudFrontAccess"
    effect = "Allow"
    actions = [
      "cloudfront:CreateInvalidation"
    ]
    resources = [
      "arn:aws:cloudfront::292999226676:distribution/E3CTNHYRFR6C3"
    ]
  }
}

##### AWS LoadBalancer Controller

module "load_balancer_controller" {
  source           = "terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"
  version          = "4.1.0"
  create_role      = true
  role_name        = "${local.cluster_name}-loadbalancer-controller"
  provider_url     = replace(module.eks.cluster_oidc_issuer_url, "https://", "")
  role_policy_arns = [aws_iam_policy.loadbalancer_controller.arn]
  oidc_fully_qualified_subjects = [
    "system:serviceaccount:kube-system:aws-load-balancer-controller",
  ]
}

resource "aws_iam_policy" "loadbalancer_controller" {
  name_prefix = "${local.cluster_name}-lb-controller"
  description = "EKS loadbalancer controller policy for cluster ${module.eks.cluster_id}"
  policy      = data.aws_iam_policy_document.loadbalancer_controller.json
}

data "aws_iam_policy_document" "loadbalancer_controller" {
  statement {
    effect    = "Allow"
    resources = ["*"]
    actions   = ["iam:CreateServiceLinkedRole"]

    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"
      values   = ["elasticloadbalancing.amazonaws.com"]
    }
  }

  statement {
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "ec2:DescribeAccountAttributes",
      "ec2:DescribeAddresses",
      "ec2:DescribeAvailabilityZones",
      "ec2:DescribeInternetGateways",
      "ec2:DescribeVpcs",
      "ec2:DescribeVpcPeeringConnections",
      "ec2:DescribeSubnets",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeInstances",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeTags",
      "ec2:GetCoipPoolUsage",
      "ec2:DescribeCoipPools",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeLoadBalancerAttributes",
      "elasticloadbalancing:DescribeListeners",
      "elasticloadbalancing:DescribeListenerCertificates",
      "elasticloadbalancing:DescribeSSLPolicies",
      "elasticloadbalancing:DescribeRules",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTargetGroupAttributes",
      "elasticloadbalancing:DescribeTargetHealth",
      "elasticloadbalancing:DescribeTags",
      "elasticloadbalancing:DescribeTrustStores",
    ]
  }

  statement {
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "cognito-idp:DescribeUserPoolClient",
      "acm:ListCertificates",
      "acm:DescribeCertificate",
      "iam:ListServerCertificates",
      "iam:GetServerCertificate",
      "waf-regional:GetWebACL",
      "waf-regional:GetWebACLForResource",
      "waf-regional:AssociateWebACL",
      "waf-regional:DisassociateWebACL",
      "wafv2:GetWebACL",
      "wafv2:GetWebACLForResource",
      "wafv2:AssociateWebACL",
      "wafv2:DisassociateWebACL",
      "shield:GetSubscriptionState",
      "shield:DescribeProtection",
      "shield:CreateProtection",
      "shield:DeleteProtection",
    ]
  }

  statement {
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupIngress",
    ]
  }

  statement {
    effect    = "Allow"
    resources = ["*"]
    actions   = ["ec2:CreateSecurityGroup"]
  }

  statement {
    effect    = "Allow"
    resources = ["arn:aws:ec2:*:*:security-group/*"]
    actions   = ["ec2:CreateTags"]

    condition {
      test     = "StringEquals"
      variable = "ec2:CreateAction"
      values   = ["CreateSecurityGroup"]
    }

    condition {
      test     = "Null"
      variable = "aws:RequestTag/elbv2.k8s.aws/cluster"
      values   = ["false"]
    }
  }

  statement {
    effect    = "Allow"
    resources = ["arn:aws:ec2:*:*:security-group/*"]

    actions = [
      "ec2:CreateTags",
      "ec2:DeleteTags",
    ]

    condition {
      test     = "Null"
      variable = "aws:RequestTag/elbv2.k8s.aws/cluster"
      values   = ["true"]
    }

    condition {
      test     = "Null"
      variable = "aws:ResourceTag/elbv2.k8s.aws/cluster"
      values   = ["false"]
    }
  }

  statement {
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:DeleteSecurityGroup",
    ]

    condition {
      test     = "Null"
      variable = "aws:ResourceTag/elbv2.k8s.aws/cluster"
      values   = ["false"]
    }
  }

  statement {
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "elasticloadbalancing:CreateLoadBalancer",
      "elasticloadbalancing:CreateTargetGroup",
    ]

    condition {
      test     = "Null"
      variable = "aws:RequestTag/elbv2.k8s.aws/cluster"
      values   = ["false"]
    }
  }

  statement {
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "elasticloadbalancing:CreateListener",
      "elasticloadbalancing:DeleteListener",
      "elasticloadbalancing:CreateRule",
      "elasticloadbalancing:DeleteRule",
    ]
  }

  statement {
    effect = "Allow"

    resources = [
      "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
      "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
      "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*",
    ]

    actions = [
      "elasticloadbalancing:AddTags",
      "elasticloadbalancing:RemoveTags",
    ]

    condition {
      test     = "Null"
      variable = "aws:RequestTag/elbv2.k8s.aws/cluster"
      values   = ["true"]
    }

    condition {
      test     = "Null"
      variable = "aws:ResourceTag/elbv2.k8s.aws/cluster"
      values   = ["false"]
    }
  }

  statement {
    effect = "Allow"

    resources = [
      "arn:aws:elasticloadbalancing:*:*:listener/net/*/*/*",
      "arn:aws:elasticloadbalancing:*:*:listener/app/*/*/*",
      "arn:aws:elasticloadbalancing:*:*:listener-rule/net/*/*/*",
      "arn:aws:elasticloadbalancing:*:*:listener-rule/app/*/*/*",
    ]

    actions = [
      "elasticloadbalancing:AddTags",
      "elasticloadbalancing:RemoveTags",
    ]
  }

  statement {
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "elasticloadbalancing:ModifyLoadBalancerAttributes",
      "elasticloadbalancing:SetIpAddressType",
      "elasticloadbalancing:SetSecurityGroups",
      "elasticloadbalancing:SetSubnets",
      "elasticloadbalancing:DeleteLoadBalancer",
      "elasticloadbalancing:ModifyTargetGroup",
      "elasticloadbalancing:ModifyTargetGroupAttributes",
      "elasticloadbalancing:DeleteTargetGroup",
    ]

    condition {
      test     = "Null"
      variable = "aws:ResourceTag/elbv2.k8s.aws/cluster"
      values   = ["false"]
    }
  }

  statement {
    effect = "Allow"

    resources = [
      "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
      "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
      "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*",
    ]

    actions = ["elasticloadbalancing:AddTags"]

    condition {
      test     = "StringEquals"
      variable = "elasticloadbalancing:CreateAction"

      values = [
        "CreateTargetGroup",
        "CreateLoadBalancer",
      ]
    }

    condition {
      test     = "Null"
      variable = "aws:RequestTag/elbv2.k8s.aws/cluster"
      values   = ["false"]
    }
  }

  statement {
    effect    = "Allow"
    resources = ["arn:aws:elasticloadbalancing:*:*:targetgroup/*/*"]

    actions = [
      "elasticloadbalancing:RegisterTargets",
      "elasticloadbalancing:DeregisterTargets",
    ]
  }

  statement {
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "elasticloadbalancing:SetWebAcl",
      "elasticloadbalancing:ModifyListener",
      "elasticloadbalancing:AddListenerCertificates",
      "elasticloadbalancing:RemoveListenerCertificates",
      "elasticloadbalancing:ModifyRule",
    ]
  }
}
