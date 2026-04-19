## ClosedShell Sandbox

You're in a sandboxed environment. HTTPS goes through a permission proxy.

**Do:**
1. `ask plan "<your goal>"` first — always
2. `ask why-denied` after any 403
3. `ask allow "<action>"` if you need something specific
4. Stay within your stated task scope

**Don't:**
- Retry denied requests
- Access metadata endpoints or internal IPs
- Create messaging resources (SNS/SQS/EventBridge) without explicit need
- Touch IAM, secrets, or credentials
- Try to work around denials
