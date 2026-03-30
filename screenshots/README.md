# Screenshots

This folder is for annotated screenshots from the security assessment.

## Suggested Screenshots

| Filename | Description |
|---|---|
| `01-architecture-overview.png` | AWS architecture diagram showing all components |
| `02-prompt-injection-attack.png` | Terminal showing the curl prompt injection command and response |
| `03-credential-disclosure.png` | Redacted screenshot of credentials returned by the vulnerable endpoint |
| `04-iam-wildcard-policy.png` | IAM console showing the overly broad Lambda execution role |
| `05-bedrock-guardrails.png` | Bedrock Guardrails configuration in the AWS console |
| `06-cloudwatch-logs-before.png` | CloudWatch showing sensitive data in logs (before fix) |
| `07-cloudwatch-logs-after.png` | CloudWatch showing clean structured logs (after fix) |
| `08-api-gateway-auth.png` | API Gateway console showing Cognito authoriser configured |

## Notes

- Redact any real credentials or account IDs before committing screenshots
- Use the AWS console dark mode for a consistent visual style
- Annotate screenshots with red boxes or arrows to highlight the key finding
