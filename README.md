# SPIRE Controller Manager Dynamic Registration

[![Apache 2.0 License](https://img.shields.io/github/license/spiffe/helm-charts)](https://opensource.org/licenses/Apache-2.0)
[![Development Phase](https://github.com/spiffe/spiffe/blob/main/.img/maturity/dev.svg)](https://github.com/spiffe/spiffe/blob/main/MATURITY.md#development)

A server and agent set of helpers to register non Kubernetes node attestors with the spire server so the spire-controller-manager can use them.

## Warning

This code is very early in development and is very experimental. Please do not use it in production yet. Please do consider testing it out, provide feedback,
and maybe provide fixes.

## How it Works

The registration agent runs as a sidecar to the spire-agent. It loads the agent's svid and contacts the registration server using it and a kubernetes psat.

The registration server verifies the agents svid and k8s psat. If they all check out, it registers it with the spire-server.
