# CloudForge

Self-hosted Windows RDP/SSH builder bot. A Telegram engine on GitHub Actions
provisions short-lived `windows-2022` runners and keeps them reachable through
`bore` and a Cloudflare quick tunnel.

## What it is

- `bot-engine.yml` runs the Telegram bot from `engine/core.vault`.
- `cloud-node.yml` runs the Windows agent from `engine/node.vault`.
- All state travels through encrypted assets on the `cloudbus` release tag.
- Nothing is readable without the repository secrets.

## Setup

1. Create a public GitHub repository and push this directory.
2. Create the secrets (the keys are read from the environment at build time):

```
gh secret set CLOUDBOT_TOKEN        # BotFather token
gh secret set CLOUDBOT_OWNER_ID     # your Telegram user id
gh secret set BUS_KEY               # asset encryption key
gh secret set CLOUDBOT_VAULT_KEY    # engine vault key
gh secret set NODE_VAULT_KEY        # node vault key
```

3. Open Actions and run `bot-engine` once manually.
4. Send `/start` to the bot. Add credit with `/addcredits` as the owner, then
   `/new` to spawn a machine.

## Warning

These runners are shared, ephemeral and untrusted. Never sign in to personal
accounts, stores, email, or wallets on them. Assume anything typed or stored on
a node is copied. Automated provisioning may violate provider terms; use at
your own risk.
