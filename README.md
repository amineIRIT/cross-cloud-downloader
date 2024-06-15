# cross-cloud-downloader

## Description

Cross-cloud is a strategy followed by organisations to use services provided by multiple cloud service providers. To provide a seamless experience, IAM interoperability issues need to be addressed. Current approaches involve relying on a third party cloud broker which causes known-problems that originally led to the concept of cross-cloud. In this article, we analyze the IAM interoperability issues when building a cross-cloud environment on top of the current major cloud service providers (Amazon Web Service, Microsoft Azure and Google Cloud Platform) by implementing a cross-cloud storage application. This experiment demonstrates the need to integrate new identity management systems to cloud IAM services in the future.

## Files description

### Locally managed accounts.py

This file represents the first experimentation thet takes advantage of the access credentials provided by the CSP for external use (usually reserved for workflows and applications) using locally managed accounts.

### OIDC_AWS_PKCE.py & OIDC_GCP_PKCE.py
For this second experimentation, our goal is to have control over the authentication process in order to implement a unique identity management solution. Therefore, we used Open Id Connect (OIDC) which is an authentication protocol based on OAuth 2.0 that allows the verification of user identities via an authorization server and issue tokens to prove the success of the authentication. 

