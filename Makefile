# Makefile for nginx-cert-manager agent and worker

# Variables
REGISTRY ?= docker.asean-accesstrade.net
NAMESPACE ?= nginx-cert-manager
VERSION ?= latest

# Agent specific variables
AGENT_IMAGE_NAME ?= library/nginx-cert-manager
AGENT_DEPLOYMENT_NAME ?= nginx-cert-manager-agent
AGENT_CONTAINER_NAME ?= agent

# Worker specific variables
WORKER_IMAGE_NAME ?= library/nginx-cert-manager-worker
WORKER_DEPLOYMENT_NAME ?= nginx-cert-manager-worker
WORKER_CONTAINER_NAME ?= worker

# Full image tags
AGENT_IMAGE_TAG = $(REGISTRY)/$(AGENT_IMAGE_NAME):$(VERSION)
WORKER_IMAGE_TAG = $(REGISTRY)/$(WORKER_IMAGE_NAME):$(VERSION)

.PHONY: all build build-agent build-worker push push-agent push-worker clean

# Default target: build and push both images
all: build push

# Build both images
build: build-agent build-worker

# Build the Agent Docker image
# Assumes the same Dockerfile is used for both, just tagged differently.
# If worker needs a different Dockerfile (e.g., Dockerfile.worker), adjust build-worker target.
build-agent:
	@echo "Building Agent Docker image: $(AGENT_IMAGE_TAG)"
	docker build -t $(AGENT_IMAGE_TAG) .

# Build the Worker Docker image
build-worker:
	@echo "Building Worker Docker image: $(WORKER_IMAGE_TAG) using Dockerfile.worker"
	docker build -t $(WORKER_IMAGE_TAG) -f Dockerfile.worker .
# Push both images
push: push-agent push-worker

# Push the Agent Docker image to the registry
push-agent:
	@echo "Pushing Agent Docker image: $(AGENT_IMAGE_TAG)"
	docker push $(AGENT_IMAGE_TAG)

# Push the Worker Docker image to the registry
push-worker:
	@echo "Pushing Worker Docker image: $(WORKER_IMAGE_TAG)"
	docker push $(WORKER_IMAGE_TAG)

# Update both deployments
update-deployments: update-agent update-worker

# Update the Agent Kubernetes deployment with the new image tag
update-agent:
	@echo "Updating deployment $(AGENT_DEPLOYMENT_NAME) in namespace $(NAMESPACE) to image $(AGENT_IMAGE_TAG)"
	kubectl set image deployment/$(AGENT_DEPLOYMENT_NAME) $(AGENT_CONTAINER_NAME)=$(AGENT_IMAGE_TAG) -n $(NAMESPACE)
	@echo "Agent deployment update initiated. Rolling status check:"
	kubectl rollout status deployment/$(AGENT_DEPLOYMENT_NAME) -n $(NAMESPACE)

# Update the Worker Kubernetes deployment with the new image tag
update-worker:
	@echo "Updating deployment $(WORKER_DEPLOYMENT_NAME) in namespace $(NAMESPACE) to image $(WORKER_IMAGE_TAG)"
	kubectl set image deployment/$(WORKER_DEPLOYMENT_NAME) $(WORKER_CONTAINER_NAME)=$(WORKER_IMAGE_TAG) -n $(NAMESPACE)
	@echo "Worker deployment update initiated. Rolling status check:"
	kubectl rollout status deployment/$(WORKER_DEPLOYMENT_NAME) -n $(NAMESPACE)

# Clean up local Docker images (optional)
clean:
	@echo "Removing local Docker images: $(AGENT_IMAGE_TAG) $(WORKER_IMAGE_TAG)"
	docker rmi $(AGENT_IMAGE_TAG) || true
	docker rmi $(WORKER_IMAGE_TAG) || true

# Example usage:
# make                      # Builds & pushes both 'latest' images
# make VERSION=1.0.1        # Builds & pushes both '1.0.1' images
# make build                # Builds both 'latest' images
# make build VERSION=1.0.1  # Builds both '1.0.1' images
# make push VERSION=1.0.1   # Pushes both '1.0.1' images
# make update-deployments VERSION=1.0.1 # Updates both deployments to '1.0.1'
# make build-agent          # Only builds agent 'latest'
# make push-worker VERSION=1.0.1 # Only pushes worker '1.0.1'
# make update-agent VERSION=1.0.1 # Only updates agent deployment to '1.0.1'
# make all update-deployments # Build, push, and update both deployments with 'latest' tag
