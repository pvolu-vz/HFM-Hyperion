# Veza OAA Integration Agent — VS Code Setup Guide

A VS Code workspace that gives you a custom **GitHub Copilot agent** and **skill** for generating production-ready [Veza OAA](https://docs.veza.com/4yItIzMvkpAvMVFAamTf/developers/api/oaa/getting-started) connector scripts from scratch — including the Python integration, installer, `.env` template, `requirements.txt`, and deployment README.

---

## Prerequisites

| Requirement | Minimum version / notes |
|---|---|
| **VS Code** | 1.99+ (required for `.github/agents/` and `.github/skills/` auto-discovery) |
| **GitHub Copilot extension** | Latest — must be signed in with a **Copilot Pro** (or higher) seat |
| **GitHub Copilot Chat extension** | Latest — agent mode must be enabled (see [Step 3](#3-enable-agent-mode)) |
| **Python** | 3.9+ — only needed to run the generated integrations, not to use the agent |
| **Git** | Any recent version |

---

## 1. Clone & Open the Repo

**One click** — VS Code clones the repo and opens the correct root folder automatically:

[![Open in VS Code](https://img.shields.io/badge/Open%20in-VS%20Code-blue?logo=visualstudiocode)](vscode://vscode.git/clone?url=https://github.com/pvolu-vz/OAA_Agent.git)

<details>
<summary>Prefer the terminal?</summary>

```bash
git clone https://github.com/pvolu-vz/OAA_Agent.git
cd OAA_Agent
code .
```

> **Important:** Open the **root folder** (`OAA_Agent/`), not a subfolder. VS Code only auto-discovers `.github/agents/` and `.github/skills/` when the workspace root contains them.

</details>

---

## 2. Repo Structure

```
OAA_Agent/
├── .github/
│   ├── agents/
│   │   └── veza-oaa-integration.agent.md   ← custom agent definition
│   └── skills/
│       └── veza-oaa-integration/
│           ├── SKILL.md                    ← skill instructions
│           └── references/                 ← artifact specs & quality checklist
└── integrations/                           ← generated connector output lands here
    └── <system-slug>/
        ├── <system_name>.py
        ├── install_<system_name>.sh
        ├── requirements.txt
        ├── .env.example
        ├── README.md
        └── samples/
```

---

## 3. Enable Agent Mode

1. Open the **Copilot Chat** panel: `⌘ Shift I` (macOS) / `Ctrl Shift I` (Windows/Linux), or click the chat icon in the Activity Bar.
2. In the chat input area, click the **mode selector dropdown** (shows "Ask" by default) and choose **Agent**.
3. Confirm you see agent mode is active — the input bar will show `@` suggestions.

> If you don't see the mode dropdown, update the GitHub Copilot Chat extension to the latest version.

---

## 4. Using the Custom Agent

The custom agent handles the full end-to-end workflow: it gathers requirements, reads any data samples you provide, generates all integration files, and runs a quality check.

### Invoke the agent

In Copilot Chat (Agent mode), mention the agent by name:

```
@Veza OAA Integration Script <describe what you're building>
```

### Example prompts

```
@Veza OAA Integration Script Build a connector for Workday HCM using OAuth2 client credentials.
Users and groups should map to Veza local users and roles.
```

```
@Veza OAA Integration Script I have a CSV export of our internal Access DB with columns: user_id, resource_name, permission_level.
Build an OAA integration that reads this file and pushes to Veza.
```

```
@Veza OAA Integration Script Create an OAA connector for a PostgreSQL database. I need to model
database roles as Veza roles and tables as resources with SELECT/INSERT/UPDATE/DELETE permissions.
```

### What the agent does

| Step | What happens |
|---|---|
| **1 — Gather requirements** | If your prompt doesn't answer all required questions (system name, data source type, entity model, permission model), the agent asks before writing any code. |
| **2 — Read data samples** | If you drop sample files into `./integrations/<slug>/samples/` first, the agent reads them automatically to infer field names, entity structure, and permission values. |
| **3 — Generate artifacts** | Creates all files under `./integrations/<system-slug>/`: Python script, shell installer, `requirements.txt`, `.env.example`, and integration-level `README.md`. |
| **4 — Quality check** | Reviews generated files against a security and completeness checklist before finishing. |

### Accelerate with data samples

Before invoking the agent, drop a small data sample into the expected path and the agent will use it automatically — no extra prompting needed:

```bash
mkdir -p integrations/<system-slug>/samples
cp ~/Downloads/export.csv integrations/<system-slug>/samples/
```

Accepted formats: CSV, XLSX, JSON API response snippets, SQL `DESCRIBE TABLE` output.

---

## 5. Using the Skill (without switching modes)

The **skill** activates automatically in the default Copilot Ask/Chat mode when your message contains any of these trigger phrases:

| Trigger phrase | Example |
|---|---|
| `OAA connector` | "Help me build an OAA connector for ServiceNow" |
| `OAA integration` | "I need to create an OAA integration for our data lake" |
| `push to Veza` | "How do I push HR data to Veza?" |
| `Veza provider` | "Set up a Veza provider for our internal LDAP" |
| `CustomApplication` | "Model permissions with CustomApplication for this REST API" |
| `identity data` | "Push identity data from our HR system to Veza" |
| `permission data` | "Push permission data from Oracle to Veza" |
| `REST API connector` | "Build a REST API connector for Veza OAA" |
| `CSV to Veza` | "I want to import a CSV to Veza via OAA" |
| `database connector` | "Create a database connector for Veza" |
| `data lake connector` | "Build a data lake connector for Veza" |
| `HR system integration` | "HR system integration with Veza OAA" |

The skill loads the full OAA domain knowledge into context so Copilot answers with accurate SDK usage, template selection, and code patterns — even without the dedicated agent.

---

## 6. Troubleshooting

**The `@Veza OAA Integration Script` agent doesn't appear in the `@` picker**
- Confirm VS Code is ≥ 1.99: `Help → About`.
- Confirm you opened the **root** `OAA_Agent/` folder, not a subfolder.
- Reload the window: `⌘ Shift P` → `Developer: Reload Window`.
- Check the `.github/agents/veza-oaa-integration.agent.md` file exists and has valid YAML frontmatter.

**Generated files appear in the wrong location**
- The agent writes all output to `./integrations/<slug>/` relative to the workspace root.
- If files appear elsewhere, confirm the workspace root is `OAA_Agent/` and not a parent folder.

**The skill doesn't seem to load / Copilot gives generic answers**
- Use one of the exact trigger phrases listed in [Section 5](#5-using-the-skill-without-switching-modes).
- Ensure you're in **Ask** or **Chat** mode (not Agent mode, which uses the agent instead).
- Try rephrasing: e.g., "Build an OAA connector for ..." is a reliable trigger.

**Agent asks too many questions when I've already described the system**
- Include in your first message: system name, data source type + auth method, entity types (users/groups/roles/resources), and permission names. The agent skips the Q&A when all required fields are present.
