# CloudTrail -> least-privilege acceptance report

Baseline ('before') is the common rejected policy shape: service-wide wildcards (`s3:*`, `dynamodb:*`, ...) on `Resource: "*"`, synthesized from the services observed in each log group. The generated ('after') policy grants only the exact IAM actions that were called, scoped to the concrete resource ARNs present in the logs. Actions that AWS only supports on `Resource: "*"` (e.g. `ec2:Describe*`) remain wildcard-resource by necessity.

### Data pipeline (S3/DynamoDB/KMS/Lambda/EC2)

| Metric | Before (wildcard) | After (least privilege) |
| --- | ---: | ---: |
| Granted actions (expanded) | 1223 | 10 |
| Action reduction | — | 1213 (99.18%) |
| Statements | 1 | 8 |
| Services | 5 | 5 |
| `Resource: "*"` statements | 1 | 1 |
| Actions on `Resource: "*"` | 1223 | 2 |
| Concrete resource ARNs | 0 | 7 |

Coverage: 11/11 observed calls covered; unrelated actions: 0; least-privilege verified: True

### Web API (DynamoDB/SQS/Lambda/Secrets Manager/STS)

| Metric | Before (wildcard) | After (least privilege) |
| --- | ---: | ---: |
| Granted actions (expanded) | 253 | 9 |
| Action reduction | — | 244 (96.44%) |
| Statements | 1 | 7 |
| Services | 5 | 5 |
| `Resource: "*"` statements | 1 | 1 |
| Actions on `Resource: "*"` | 253 | 1 |
| Concrete resource ARNs | 0 | 5 |

Coverage: 9/9 observed calls covered; unrelated actions: 0; least-privilege verified: True

### Security ops (IAM/S3/EC2/SNS)

| Metric | Before (wildcard) | After (least privilege) |
| --- | ---: | ---: |
| Granted actions (expanded) | 1201 | 7 |
| Action reduction | — | 1194 (99.42%) |
| Statements | 1 | 5 |
| Services | 4 | 4 |
| `Resource: "*"` statements | 1 | 1 |
| Actions on `Resource: "*"` | 1201 | 3 |
| Concrete resource ARNs | 0 | 3 |

Coverage: 7/7 observed calls covered; unrelated actions: 0; least-privilege verified: True

## Cross-group summary

| Group | Calls covered | Actions before -> after | Reduction | Actions on `Resource:*` before -> after | Concrete ARNs | Verified |
| --- | ---: | ---: | ---: | ---: | ---: | :---: |
| 01-data-pipeline | 11/11 | 1223 -> 10 | 99.18% | 1223 -> 2 | 7 | PASS |
| 02-web-api | 9/9 | 253 -> 9 | 96.44% | 253 -> 1 | 5 | PASS |
| 03-security-ops | 7/7 | 1201 -> 7 | 99.42% | 1201 -> 3 | 3 | PASS |
