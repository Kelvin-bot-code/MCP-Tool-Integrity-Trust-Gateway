# Internal API Gateway & Microservices Architecture Specification

Document ID: ARCH-GW-2026-01
Author: Elena Rostova, Infrastructure Lead
Status: APPROVED

## 1. Overview
The Core API Gateway acts as the unified reverse proxy and protocol bridge for all incoming external requests and agent tooling.

## 2. Ingress Specifications
- Protocol: HTTP/2 and WebSocket
- Ingress Rate Limiting: 500 requests per second per IP block
- Timeout: Standard timeout is 30 seconds; streaming LLM responses allow up to 120 seconds
- Header Sanitization: All incoming authorization headers are validated against the OAuth2/OIDC provider

## 3. Tool Communication
Tools invoking external services must transit through the gateway egress proxy. 
Direct outbound socket access is prohibited without explicit security review.
