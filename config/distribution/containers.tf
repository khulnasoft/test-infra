data "http" "diginfra_readme" {
  url = "https://raw.githubusercontent.com/khulnasoft/diginfra/master/README.md"
}

resource "aws_ecrpublic_repository" "diginfra" {
  provider = aws.us

  repository_name = "diginfra"

  catalog_data {
    description       = "A simple daemon to help you with khulnasoft's outputs"
    about_text        = substr(data.http.diginfra_readme.body, 0, 10240)
    architectures     = ["x86-64"]
    operating_systems = ["Linux"]
  }

  lifecycle {
    prevent_destroy = true
  }
}

data "http" "diginfra_ui_readme" {
  url = "https://raw.githubusercontent.com/khulnasoft/diginfra-ui/master/README.md"
}

resource "aws_ecrpublic_repository" "diginfra_ui" {
  provider = aws.us

  repository_name = "diginfra-ui"

  catalog_data {
    description       = "A simple WebUI with latest events from Khulnasoft"
    about_text        = substr(data.http.diginfra_ui_readme.body, 0, 10240)
    architectures     = ["x86-64"]
    operating_systems = ["Linux"]
  }

  lifecycle {
    prevent_destroy = true
  }
}

data "http" "khulnasoft_readme" {
  url = "https://raw.githubusercontent.com/khulnasoft/khulnasoft/master/README.md"
}

resource "aws_ecrpublic_repository" "khulnasoft" {
  provider = aws.us

  repository_name = "khulnasoft"

  catalog_data {
    description       = "Container Native Runtime Security for Cloud Native Platforms"
    about_text        = substr(data.http.khulnasoft_readme.body, 0, 10240)
    architectures     = ["x86-64", "ARM 64"]
    operating_systems = ["Linux"]
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ecrpublic_repository" "khulnasoft_driver_loader" {
  provider = aws.us

  repository_name = "khulnasoft-driver-loader"

  catalog_data {
    description       = "Container Native Runtime Security for Cloud Native Platforms"
    about_text        = substr(data.http.khulnasoft_readme.body, 0, 10240)
    architectures     = ["x86-64", "ARM 64"]
    operating_systems = ["Linux"]
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ecrpublic_repository" "khulnasoft_no_driver" {
  provider = aws.us

  repository_name = "khulnasoft-no-driver"

  catalog_data {
    description       = "Container Native Runtime Security for Cloud Native Platforms"
    about_text        = substr(data.http.khulnasoft_readme.body, 0, 10240)
    architectures     = ["x86-64", "ARM 64"]
    operating_systems = ["Linux"]
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ecrpublic_repository" "khulnasoft_distroless" {
  provider = aws.us

  repository_name = "khulnasoft-distroless"

  catalog_data {
    description       = "Container Native Runtime Security for Cloud Native Platforms"
    about_text        = substr(data.http.khulnasoft_readme.body, 0, 10240)
    architectures     = ["x86-64", "ARM 64"]
    operating_systems = ["Linux"]
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ecrpublic_repository" "khulnasoft_driver_loader_legacy" {
  provider = aws.us

  repository_name = "khulnasoft-driver-loader-legacy"

  catalog_data {
    description       = "Container Native Runtime Security for Cloud Native Platforms"
    about_text        = substr(data.http.khulnasoft_readme.body, 0, 10240)
    architectures     = ["x86-64", "ARM 64"]
    operating_systems = ["Linux"]
  }

  lifecycle {
    prevent_destroy = true
  }
}

data "http" "khulnasoftctl_readme" {
  url = "https://raw.githubusercontent.com/khulnasoft/khulnasoftctl/main/README.md"
}

resource "aws_ecrpublic_repository" "khulnasoftctl" {
  provider = aws.us

  repository_name = "khulnasoftctl"

  catalog_data {
    description       = "Administrative tooling for Khulnasoft"
    about_text        = substr(data.http.khulnasoftctl_readme.body, 0, 10200)
    architectures     = ["x86-64", "ARM 64"]
    operating_systems = ["Linux"]
  }

  lifecycle {
    prevent_destroy = true
  }
}
