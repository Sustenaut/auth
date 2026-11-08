terraform {
  required_version = ">= 1.11"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.13"
    }
  }

  # State is in the bucket every Sustenaut stack uses, one prefix per repository
  # (Sustenaut/shared-infra's help/setup.md, step 3).
  backend "gcs" {
    bucket = "sustenaut-tfstate"
    prefix = "auth"
  }
}

provider "google" {
  project = local.gcp.project
  region  = local.gcp.region

  # With user credentials (gcloud auth application-default login), API calls
  # must name a project to bill.
  user_project_override = true
  billing_project       = local.gcp.project
}
