# Middle Agent Implementation Backlog

## Overview
Implement a middle agent component that acts as a bridge between HTTP clients and SSH-based NGINX servers:
```
Client --- (HTTP) ---> Agent ---(SSH) ---> NGINX VM
```

## User Stories

### API Development
- [ ] **API-1:** As a client application, I want to issue certificates via HTTP requests
- [ ] **API-2:** As a client application, I want to deploy certificates to NGINX servers via HTTP requests
- [ ] **API-3:** As a client application, I want to renew certificates via HTTP requests
- [ ] **API-4:** As a client application, I want to check certificate status via HTTP requests
- [ ] **API-5:** As a client application, I want to list all managed certificates via HTTP requests

### Authentication & Security
- [ ] **SEC-1:** As an administrator, I want to secure API access with API keys or JWT tokens
- [ ] **SEC-2:** As an administrator, I want to store SSH credentials securely
- [ ] **SEC-3:** As an administrator, I want to limit which VMs can be managed by specific API clients
- [ ] **SEC-4:** As an administrator, I want TLS encryption for the HTTP API

### SSH Connection Management
- [ ] **SSH-1:** As a system, I need to establish SSH connections to target VMs
- [ ] **SSH-2:** As a system, I need to execute NGINX configuration commands remotely
- [ ] **SSH-3:** As a system, I need to transfer certificate files securely to target VMs
- [ ] **SSH-4:** As a system, I need to validate NGINX configurations after deployment
- [ ] **SSH-5:** As a system, I need to restart NGINX services after deployment

### Configuration Management
- [ ] **CFG-1:** As an administrator, I want to register and manage target NGINX servers
- [ ] **CFG-2:** As an administrator, I want to configure SSH connection details (username, keys, etc.)
- [ ] **CFG-3:** As an administrator, I want to map certificates to specific NGINX virtual hosts

### Logging & Monitoring
- [ ] **LOG-1:** As an administrator, I want to log all certificate operations
- [ ] **LOG-2:** As an administrator, I want to monitor certificate expiration dates
- [ ] **LOG-3:** As an administrator, I want to receive notifications about failed operations
- [ ] **LOG-4:** As an administrator, I want to audit all API and SSH activities

## Technical Tasks

### HTTP Server Implementation
- [ ] Create a web server using Flask/FastAPI
- [ ] Design RESTful API endpoints for certificate operations
- [ ] Implement request validation and error handling
- [ ] Implement authentication middleware
- [ ] Add rate limiting to prevent abuse

### SSH Connection Module
- [ ] Extend existing SSH utilities for session management
- [ ] Implement connection pooling for frequently accessed VMs
- [ ] Create retry mechanism for failed SSH operations
- [ ] Develop templating system for NGINX configuration commands

### Certificate Management
- [ ] Connect Let's Encrypt module to HTTP API
- [ ] Create certificate storage and retrieval system
- [ ] Implement certificate renewal tracking
- [ ] Develop certificate deployment workflow

### Database Integration
- [ ] Design database schema for servers, certificates, and operations
- [ ] Implement ORM models
- [ ] Create data access layer
- [ ] Add migration system for schema updates

### Deployment & Operations
- [ ] Containerize the middle agent
- [ ] Create configuration for different environments
- [ ] Set up logging and monitoring
- [ ] Design backup and recovery procedures

## Architecture Design

### Components
- **HTTP API Layer**: Handle client requests, authentication, and response formatting
- **Core Logic Layer**: Certificate operations, workflow management
- **SSH Connection Layer**: VM communication, command execution, file transfers
- **Storage Layer**: Database for configuration and operational data
- **Monitoring & Logging**: Tracking system activities

### Communication Flow
1. Client sends HTTP request to API
2. API authenticates and validates request
3. Core logic processes the request
4. SSH layer executes necessary commands on target VM
5. Results are collected and returned to client

## Implementation Phases

### Phase 1: Core Functionality
- Basic HTTP server
- SSH connection management
- Certificate issuance and deployment
- Simple storage

### Phase 2: Security & Reliability
- Authentication system
- Error handling improvements
- Connection pooling
- Database integration

### Phase 3: Advanced Features
- Monitoring and alerting
- Batch operations
- Certificate renewal automation
- Performance optimization

### Phase 4: Production Readiness
- Comprehensive testing
- Documentation
- Containerization
- CI/CD integration