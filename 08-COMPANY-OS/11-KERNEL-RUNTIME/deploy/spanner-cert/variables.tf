variable "project_id" {
  description = "Existing GCP project used only for Company Kernel Spanner certification."
  type        = string
  default     = "cfhs-kernel-cert"
}

variable "instance_id" {
  description = "Spanner certification instance ID."
  type        = string
  default     = "kernel-ha-cert-01"
}

variable "database_id" {
  description = "Company Kernel certification database ID."
  type        = string
  default     = "cfhs-cert"
}

variable "instance_config" {
  description = "Spanner instance configuration. Regional certification starts in us-central1; topology evidence must bind the deployed value."
  type        = string
  default     = "regional-us-central1"
}

variable "processing_units" {
  description = "Certification capacity. Intentionally small; change only with explicit cost review."
  type        = number
  default     = 100
  validation {
    condition     = var.processing_units >= 100
    error_message = "Spanner certification processing_units must be at least 100."
  }
}
