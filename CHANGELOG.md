# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses semantic versioning.

## [Unreleased]

## [0.1.0]

### Added

- Normalizers for Splunk, Microsoft Sentinel, CrowdStrike, Elastic and generic JSON Lines alerts.
- Correlation of alerts into incidents with noise and hub filtering.
- Investigation with timeline, indicator matching, asset and identity context, ATT&CK mapping, rule-based
  hypotheses and an explained risk score.
- Containment proposals with protected targets, senior approval, dependencies and approval expiry.
- Approval, rejection and execution workflow with dry-run and webhook connectors.
- Hash-chained audit log with `audit --verify`.
- Markdown and JSON incident reports, and an optional model-written summary that only sees aggregate facts.
- Deterministic multi-vendor simulator, command-line interface, Docker image and CI workflows.
