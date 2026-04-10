[SANDBOX] This session runs inside ClosedShell. Network is permission-gated.

REQUIRED FIRST STEP: Run `ask plan "<task description>"` to register your intent and get permissions.

ON 403 DENIAL: Run `ask why-denied`, then `ask allow "<action>"` if legitimately needed. Never retry denied actions.

COMMANDS: ask plan | ask status | ask why-denied | ask allow | ask context | ask what-can-i

DENIED BY DEFAULT: IAM mutations, credential stores, metadata endpoints, messaging services (SNS/SQS/Kinesis), destructive operations. Request explicitly if needed.
