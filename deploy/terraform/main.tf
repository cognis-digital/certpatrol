terraform {
  required_providers {
    docker = { source = "kreuzwerker/docker", version = "~> 3.0" }
  }
}
# Minimal container deploy. Swap the provider block for aws_ecs_service,
# azurerm_container_app, or google_cloud_run_v2_service as needed.
provider "docker" {}
resource "docker_image" "certpatrol" { name = "ghcr.io/cognis-digital/certpatrol:latest" }
resource "docker_container" "certpatrol" {
  name  = "certpatrol"
  image = docker_image.certpatrol.image_id
  ports { internal = 8000 external = 8000 }
}
