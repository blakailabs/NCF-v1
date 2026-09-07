terraform {
  required_version = ">= 1.6.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0"
    }
  }
}

provider "google" {
  project = var.project_id
}

resource "google_project_service" "spanner" {
  project            = var.project_id
  service            = "spanner.googleapis.com"
  disable_on_destroy = false
}

resource "google_spanner_instance" "kernel_cert" {
  name             = var.instance_id
  config           = var.instance_config
  display_name     = "Company Kernel HA Certification"
  processing_units = var.processing_units

  labels = {
    system      = "company-kernel"
    component   = "shared-state"
    environment = "cert"
    backend     = "spanner"
    purpose     = "ha-certification"
    managed-by  = "cfhs"
    production  = "false"
  }

  depends_on = [google_project_service.spanner]
}

resource "google_spanner_database" "cfhs_cert" {
  instance            = google_spanner_instance.kernel_cert.name
  name                = var.database_id
  database_dialect    = "GOOGLE_STANDARD_SQL"
  deletion_protection = true

  ddl = [
    "CREATE TABLE cfhs_shared_objects (object_key STRING(2048) NOT NULL, version INT64 NOT NULL, value_digest STRING(64) NOT NULL, value_json JSON NOT NULL, updated_at TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true)) PRIMARY KEY (object_key)",
    "CREATE TABLE cfhs_shared_fences (resource_key STRING(2048) NOT NULL, last_token INT64 NOT NULL, current_token INT64, owner_id STRING(512), lease_id STRING(512), expires_at TIMESTAMP, updated_at TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true)) PRIMARY KEY (resource_key)",
    "CREATE TABLE cfhs_shared_journal (stream_key STRING(2048) NOT NULL, version INT64 NOT NULL, event_digest STRING(64) NOT NULL, event_json JSON NOT NULL, committed_at TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true)) PRIMARY KEY (stream_key, version)"
  ]
}

output "deployment_identity" {
  value = {
    deployment_id = "company-kernel-cert-spanner-01"
    project_id     = var.project_id
    instance_id    = google_spanner_instance.kernel_cert.name
    database_id    = google_spanner_database.cfhs_cert.name
    backend        = "spanner"
    environment    = "cert"
  }
}
