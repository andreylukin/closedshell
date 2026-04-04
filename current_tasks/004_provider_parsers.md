# Task: Provider Parsers

**Status:** partial (generic net: and basic AWS done, needs more AWS coverage and GCP/GitHub)

**What to do:**
1. Improve AWS parser in `crates/closedshell-lib/src/parser.rs`:
   - Handle S3 REST-style requests (GET/PUT/DELETE on s3.amazonaws.com/bucket/key → map to GetObject/PutObject/DeleteObject)
   - Handle regional endpoints (s3.us-east-1.amazonaws.com, ec2.us-west-2.amazonaws.com)
   - Extract profile from env var hint passed into parse context (not just from auth header)
2. Add GCP parser:
   - Host: *.googleapis.com
   - Parse REST path: compute.googleapis.com/compute/v1/projects/{project}/zones/{zone}/instances/{id} → gcp[project={project}]:compute.instances.get
   - Extract project from path
3. Add GitHub parser:
   - Host: api.github.com
   - Method + path → gh:repos/owner/repo:METHOD or gh:repos/owner/repo/pulls:METHOD
4. Add more tests for edge cases

**Tests that must pass:**
- `cargo test -p closedshell-lib parser`

**Files:**
- `crates/closedshell-lib/src/parser.rs`
