# 墨影録 (Bokuei-roku) Licensing Decision Framework

## 1. Purpose of this Document
This document outlines the strategic, legal, and operational options for the project owners regarding the open-core versus open-source licensing model for Bokuei.

> **Note:** As an AI assistant, I do not make legal decisions or choose a business license on behalf of the project owner. This document provides the structured trade-offs and decision vectors for the owner's determination.

---

## 2. Option Comparison

| Feature Vector | Fully Permissive (Apache 2.0 / MIT) | Open-Core Model (Apache Core + Commercial Extensions) | Strong Copyleft (AGPLv3) |
| :--- | :--- | :--- | :--- |
| **Core Ledger Engine** | Permissive | Permissive | Copyleft |
| **Capture Agent (`bokuei-agent`)** | Permissive | Permissive | Copyleft |
| **Commercial Federation Registry** | Permissive | Commercial / BSL / Enterprise | Copyleft (Network copyleft triggered by API) |
| **Vendor Neutrality & Adoption** | Highest initial adoption; cloud providers can re-host without contributing | Strong community adoption for core; monetizes enterprise governance and federation | Inhibits commercial integration by companies with strict no-AGPL policies |
| **Contributions & Ecosystem** | Maximum third-party plugin and integration ecosystem | Corporate governance required (CLA or Developer Certificate of Origin) | Community-driven, protects against closed-source forks |

---

## 3. Decision Vectors for the Project Owner

1. **Self-Hosting & Enterprise Federation:**  
   If the goal is to build an enterprise multi-tenant registry with role-based access control (RBAC), SSO, and audited compliance workflows, an open-core model with an Apache-2.0 core and a commercial registry module is standard industry practice.
2. **Third-Party Plugin Ecosystem:**  
   The declarative TOML plugin schema (`plugins/*.toml`) relies on broad domain contribution (AI models, quantum backends, blockchain clients). A permissive license for plugin definitions encourages community contribution without legal friction.
3. **Patent Grant & Trademark:**  
   The Apache 2.0 license includes explicit patent grants and protects the Bokuei name via trademark restrictions, making it generally preferable over pure MIT for infrastructure software.

---

## 4. Current Repository License
For development and core tooling evaluation, the repository components adhere to standard permissive terms pending final corporate sign-off.
