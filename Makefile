# Makefile for nginx-cert-manager agent

# Variables
REGISTRY ?= registry.asean-accesstrade.net
IMAGE_NAME ?= library/nginx-cert-manager
NAMESPACE ?= nginx-cert-manager
DEPLOYMENT_NAME ?= nginx-cert-manager-agent
CONTAINER_NAME ?= agent
VERSION ?= latest

# Full image tag
IMAGE_TAG = $(REGISTRY)/$(IMAGE_NAME):$(VERSION)

.PHONY: all build push update-deployment clean

all: build push update-deployment

# Build the Docker image
build:
	@echo "Building Docker image: $(IMAGE_TAG)"
	docker build -t $(IMAGE_TAG) .

# Push the Docker image to the registry
push:
	@echo "Pushing Docker image: $(IMAGE_TAG)"
	docker push $(IMAGE_TAG)

# Update the Kubernetes deployment with the new image tag
update-deployment:
	@echo "Updating deployment $(DEPLOYMENT_NAME) in namespace $(NAMESPACE) to image $(IMAGE_TAG)"
	kubectl set image deployment/$(DEPLOYMENT_NAME) $(CONTAINER_NAME)=$(IMAGE_TAG) -n $(NAMESPACE)
	@echo "Deployment update initiated. Rolling status check:"
	kubectl rollout status deployment/$(DEPLOYMENT_NAME) -n $(NAMESPACE)

# Clean up local Docker image (optional)
clean:
	@echo "Removing local Docker image: $(IMAGE_TAG)"
	docker rmi $(IMAGE_TAG) || true

# Example usage:
# make                # Builds, pushes, updates deployment with 'latest' tag
# make VERSION=1.0.1  # Builds, pushes, updates deployment with '1.0.1' tag
# make build          # Only builds 'latest'
# make build VERSION=1.0.1 # Only builds '1.0.1'
# make push VERSION=1.0.1  # Only pushes '1.0.1'
# make update-deployment VERSION=1.0.1 # Only updates deployment to '1.0.1'
