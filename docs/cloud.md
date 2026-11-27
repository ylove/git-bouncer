# Cloud runtimes: GCP Cloud Build and AWS CodeBuild

> **Not live-tested by the maintainer, because it costs money.**
>
> These runtimes are built and unit-tested: every generated build file and every command line has a test, and no test talks to a real cloud. But nobody has run them against a real Google Cloud project or AWS account. Treat them as a careful starting point for your own setup, read what they would do with `--dry-run` first, and please [open an issue](https://github.com/ylove/git-bouncer/issues) if something doesn't work.

Most people should use the local sandbox (Docker or Podman) or the Codespaces fallback. The cloud runtimes are for people who would rather run the check in their own cloud account, signed in with `gcloud` or `aws`. They are opt-in only: git-bouncer never picks them unless you pass `--runtime gcp` or `--runtime aws`.

## What they do

Both runtimes do the same thing a local scan does, on a throwaway machine in your account:

1. Copy git-bouncer's own `sandbox/` folder (the Dockerfile and the scanner) to a private temporary folder on your machine.
2. Upload that copy to your cloud account: Cloud Build's staging bucket on GCP, or an S3 bucket you choose on AWS. **Nothing else from your machine is uploaded, and nothing from the repository being checked.** The scanner clones the repository itself, inside the sandbox.
3. Start a build that (a) builds the sandbox image from that folder and (b) runs it with the same locked-down settings as a local scan: no Linux capabilities, read-only filesystem, an unprivileged user, size-limited `noexec` scratch space, process and memory limits, and **no credentials, mounts or environment variables**.
4. Wait for the build, then read the build log. The report sits in the log between two marker lines that contain a random value (the nonce) chosen by your machine for this scan.
5. Clean up: delete the uploaded copy and the temporary folder. If git-bouncer stops waiting (you press Ctrl-C, or it times out) while the build is still running, it cancels the build so nothing keeps billing.

The cloud machines are deleted when the build ends, so there is nothing to inspect afterwards. `--keep` has no effect with these runtimes.

### See exactly what would run

```sh
bouncer scan https://github.com/owner/repo --runtime gcp --dry-run
bouncer scan https://github.com/owner/repo --runtime aws --dry-run
```

A dry run runs no commands and calls no cloud API. It prints every command, in order, as the exact argument list git-bouncer would pass to `gcloud` or `aws`. It also prints the generated files (`cloudbuild.yaml`, or `start-build.json` and `buildspec.yml`) and notes on what gets uploaded and where. Values that only exist once a build has started, such as the build ID, are shown as `<build-id>`. (The `--dry-run` flag is wired into the CLI separately from these runtimes; under the hood it is each runtime's `plan()`.)

## What it costs

Running a scan uses paid services in **your** account. git-bouncer doesn't quote prices because they change and depend on your region, machine type and free-tier status. Check the official pricing pages:

| | Google Cloud | AWS |
|---|---|---|
| Build minutes (the main cost) | [Cloud Build pricing](https://cloud.google.com/build/pricing) | [CodeBuild pricing](https://aws.amazon.com/codebuild/pricing/) |
| Storing the uploaded sandbox folder (a few KB, deleted after each scan) | [Cloud Storage pricing](https://cloud.google.com/storage/pricing) | [S3 pricing](https://aws.amazon.com/s3/pricing/) |
| Keeping build logs | [Cloud Logging pricing](https://cloud.google.com/stackdriver/pricing) | [CloudWatch pricing](https://aws.amazon.com/cloudwatch/pricing/) |

Each scan builds the sandbox image from scratch (there is no cache to reuse between builds) and then scans. Expect a few minutes of build time per scan, more for repositories with many dependencies. To cap the bill:

- Every build has its own time limit: **30 minutes** to run and **15 minutes** to get started. The limits hold even if git-bouncer itself crashes or loses its network connection, so the worst case is one build running to its limit.
- AWS builds never retry automatically (`autoRetryLimitOverride: 0`), so a failed scan is never quietly run and billed again.
- Set a [budget alert](https://cloud.google.com/billing/docs/how-to/budgets) on GCP or an [AWS Budget](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html) before you start.

## Google Cloud (Cloud Build)

### One-time setup

You need the [Google Cloud CLI](https://cloud.google.com/sdk/docs/install) and a project with billing enabled.

```sh
gcloud auth login
gcloud config set project <project-id>
gcloud services enable cloudbuild.googleapis.com
```

That's enough to run a scan, as long as your account can create builds and use the Cloud Build staging bucket. Project Owner or Editor can; otherwise you need **Cloud Build Editor** (`roles/cloudbuild.builds.editor`), write access to the `<project-id>_cloudbuild` bucket, and permission to view build logs.

**Recommended: a dedicated service account that can do almost nothing.** Without one, the build runs as your project's default Cloud Build service account, which in many projects has broad permissions. The sandbox never gets that account's credentials (see [Security notes](#security-notes)), but nothing in a scan needs them, so don't hand them out:

```sh
PROJECT=<project-id>
gcloud iam service-accounts create git-bouncer-scan --display-name="git-bouncer scans"
SA="git-bouncer-scan@${PROJECT}.iam.gserviceaccount.com"

# Write the build log, and download the uploaded sandbox folder. Nothing else.
gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:$SA" --role=roles/logging.logWriter
gcloud storage buckets create "gs://${PROJECT}_cloudbuild"   # skip if it already exists
gcloud storage buckets add-iam-policy-binding "gs://${PROJECT}_cloudbuild" --member="serviceAccount:$SA" --role=roles/storage.objectViewer

# Let yourself start builds that run as it.
gcloud iam service-accounts add-iam-policy-binding "$SA" --member="user:$(gcloud config get-value account)" --role=roles/iam.serviceAccountUser
```

Then tell git-bouncer to use it (see [Settings](#settings)). Cloud Build requires builds with your own service account to log to Cloud Logging, so git-bouncer sets `logging: CLOUD_LOGGING_ONLY` for them. See [Configure user-specified service accounts](https://cloud.google.com/build/docs/securing-builds/configure-user-specified-service-accounts).

### What runs

```text
gcloud builds submit <temp-dir>/source --config=<temp-dir>/cloudbuild.yaml --project=<project> --async --format=value(id) --quiet
gcloud builds log <build-id> --stream --project=<project> --quiet
gcloud builds describe <build-id> --project=<project> --format=json --quiet
gcloud builds log <build-id> --project=<project> --quiet
gcloud storage rm gs://<project>_cloudbuild/<the uploaded archive> --project=<project> --quiet
gcloud builds cancel <build-id> --project=<project> --quiet        # only if it's still running when git-bouncer stops waiting
```

(`--region=<region>` is added to the `builds` commands when you set a region.) The generated `cloudbuild.yaml` has two steps, both run by Google's `gcr.io/cloud-builders/docker` image with plain argument lists: `docker build` of the sandbox folder, then `docker run` of the scanner with the hardening flags. No step uses a shell.

Why it's built this way:

- **A generated file rather than `--substitutions`.** Substitutions would keep the build file fixed, but the values would then go through gcloud's `KEY=VALUE,KEY=VALUE` flag parser, and a fixed file can't leave out `--ref` when there isn't one. Instead every value is written as a quoted string by one small serializer, and the file is checked to contain no `$`, because Cloud Build expands `$NAME` anywhere in a build file. The URL, ref and nonce can't contain `$` anyway: they're validated twice before they get here.
- **The report comes from the final `gcloud builds log`, not the streamed one.** gcloud prints each chunk of a live log with its own line break, so a long report line could arrive split in two.
- **The staging bucket is gcloud's default** (`<project-id>_cloudbuild`), because gcloud checks that this bucket belongs to your project. Someone else could create a bucket with a name you'd guess, and a custom staging location skips that check. When the scan ends, git-bouncer deletes only the one archive the build used, and only from that bucket.

### Settings

| What | Environment variable | `cloud.json` key | Default |
|---|---|---|---|
| Project | `GIT_BOUNCER_GCP_PROJECT` | `gcp.project` | `gcloud config get-value project` |
| Region | `GIT_BOUNCER_GCP_REGION` | `gcp.region` | gcloud's `builds/region` setting, else `global` |
| Service account (email) | `GIT_BOUNCER_GCP_SERVICE_ACCOUNT` | `gcp.serviceAccount` | the project's default Cloud Build service account |

Only standard project IDs (`my-project-123`) are accepted, not the older domain-scoped kind (`example.com:project`).

## AWS (CodeBuild)

### One-time setup

You need the [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) (v2 recommended), signed in (`aws configure` or `aws sso login`). You then create three things, all in **one region**: an S3 bucket for the upload, an IAM role for the build, and a CodeBuild project. Replace `REGION`, `ACCOUNT_ID` and `BUCKET` below.

**1. An S3 bucket** for the uploaded sandbox folder. Use a new, private bucket just for this (new buckets block public access by default). Bucket names with dots aren't accepted. git-bouncer deletes each upload after the scan; a lifecycle rule cleans up anything a crash left behind:

```sh
aws s3api create-bucket --bucket BUCKET --region REGION --create-bucket-configuration LocationConstraint=REGION   # leave out --create-bucket-configuration in us-east-1
aws s3api put-bucket-lifecycle-configuration --bucket BUCKET --lifecycle-configuration file://lifecycle.json
```

`lifecycle.json`:

```json
{ "Rules": [ { "ID": "expire-git-bouncer-uploads", "Status": "Enabled", "Filter": { "Prefix": "git-bouncer/" }, "Expiration": { "Days": 1 } } ] }
```

**2. An IAM role for the build** (the CodeBuild "service role"). It only needs to write its own logs and read the upload. Trust policy (`trust.json`):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "codebuild.amazonaws.com" },
    "Action": "sts:AssumeRole",
    "Condition": { "StringEquals": { "aws:SourceAccount": "ACCOUNT_ID" } }
  }]
}
```

Permissions (`role-policy.json`):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "WriteBuildLogs",
      "Effect": "Allow",
      "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
      "Resource": [
        "arn:aws:logs:REGION:ACCOUNT_ID:log-group:/aws/codebuild/git-bouncer",
        "arn:aws:logs:REGION:ACCOUNT_ID:log-group:/aws/codebuild/git-bouncer:*"
      ]
    },
    {
      "Sid": "ReadTheUpload",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:GetObjectVersion"],
      "Resource": "arn:aws:s3:::BUCKET/git-bouncer/*"
    },
    {
      "Sid": "FindTheUpload",
      "Effect": "Allow",
      "Action": ["s3:ListBucket", "s3:GetBucketAcl", "s3:GetBucketLocation"],
      "Resource": "arn:aws:s3:::BUCKET"
    }
  ]
}
```

```sh
aws iam create-role --role-name git-bouncer-codebuild --assume-role-policy-document file://trust.json
aws iam put-role-policy --role-name git-bouncer-codebuild --policy-name git-bouncer-codebuild --policy-document file://role-policy.json
```

Give it nothing else. In particular, no permission to read secrets, parameters or other buckets.

**3. A CodeBuild project** (`project.json`). Privileged mode is required: CodeBuild only runs Docker inside a build in privileged mode. Use `BUILD_GENERAL1_MEDIUM` or larger: the sandbox may use up to 3 GB of memory, and `SMALL` leaves too little for Docker itself ([compute types](https://docs.aws.amazon.com/codebuild/latest/userguide/build-env-ref-compute-types.html)). No VPC, no environment variables, no secrets: git-bouncer supplies everything per build.

```json
{
  "name": "git-bouncer",
  "source": { "type": "NO_SOURCE", "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo git-bouncer sends its own buildspec with every build\n" },
  "artifacts": { "type": "NO_ARTIFACTS" },
  "environment": {
    "type": "LINUX_CONTAINER",
    "image": "aws/codebuild/standard:7.0",
    "computeType": "BUILD_GENERAL1_MEDIUM",
    "privilegedMode": true
  },
  "serviceRole": "arn:aws:iam::ACCOUNT_ID:role/git-bouncer-codebuild",
  "timeoutInMinutes": 30,
  "queuedTimeoutInMinutes": 15,
  "logsConfig": { "cloudWatchLogs": { "status": "ENABLED" }, "s3Logs": { "status": "DISABLED" } }
}
```

```sh
aws codebuild create-project --cli-input-json file://project.json --region REGION
# Build logs never expire unless you say so. Keep them for a week:
aws logs create-log-group --log-group-name /aws/codebuild/git-bouncer --region REGION
aws logs put-retention-policy --log-group-name /aws/codebuild/git-bouncer --retention-in-days 7 --region REGION
```

**4. Tell git-bouncer about them** in `~/.config/git-bouncer/cloud.json` (or the environment variables under [Settings](#settings-1)):

```json
{ "aws": { "project": "git-bouncer", "region": "REGION", "bucket": "BUCKET" } }
```

**5. Your own permissions.** The identity you run git-bouncer as needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RunScans",
      "Effect": "Allow",
      "Action": ["codebuild:BatchGetProjects", "codebuild:StartBuild", "codebuild:BatchGetBuilds", "codebuild:StopBuild"],
      "Resource": "arn:aws:codebuild:REGION:ACCOUNT_ID:project/git-bouncer"
    },
    {
      "Sid": "ReadScanLogs",
      "Effect": "Allow",
      "Action": "logs:GetLogEvents",
      "Resource": "arn:aws:logs:REGION:ACCOUNT_ID:log-group:/aws/codebuild/git-bouncer:log-stream:*"
    },
    {
      "Sid": "UploadAndDeleteTheScanner",
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::BUCKET/git-bouncer/*"
    },
    {
      "Sid": "ListUploads",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::BUCKET",
      "Condition": { "StringLike": { "s3:prefix": "git-bouncer/*" } }
    }
  ]
}
```

git-bouncer overrides the project's buildspec, source and privileged mode on every build. If your organization blocks those overrides with IAM condition keys or service control policies, StartBuild is refused and git-bouncer shows the error.

### What runs

```text
aws s3 cp <temp-dir>/source s3://BUCKET/git-bouncer/<run-id>/ --recursive --no-follow-symlinks --only-show-errors --region=REGION
aws codebuild start-build --cli-input-json=file://<temp-dir>/start-build.json --region=REGION --output=json
aws codebuild batch-get-builds --ids=<build-id> --region=REGION --output=json             # every 10 seconds until done
aws logs get-log-events --log-group-name=<log-group> --log-stream-name=<log-stream> --start-from-head --region=REGION --output=json
aws s3 rm s3://BUCKET/git-bouncer/<run-id>/ --recursive --only-show-errors --region=REGION
aws codebuild stop-build --id=<build-id> --region=REGION --output=json                    # only if it's still running when git-bouncer stops waiting
```

`<run-id>` is a random-looking value derived one-way from the scan's nonce, so the nonce itself never appears in a bucket listing.

Why it's built this way:

- **The source goes through S3** because CodeBuild has no "upload this folder" option. The alternatives were to put the scanner inside the buildspec or an environment variable (size limits, and shell commands would have to unpack it), or to have the build download git-bouncer from GitHub (then the cloud would run whatever GitHub serves, not the exact files you installed).
- **The shell text never contains a value.** CodeBuild runs buildspec commands through a shell; there is no way to pass an argument list. So the commands are fixed text, and the URL, ref and nonce arrive as environment variables that the commands only use as `"$GIT_BOUNCER_URL"`. A shell does not re-read the value of a double-quoted variable as shell syntax, so a value can't turn into a second command. A unit test checks that the buildspec is byte-for-byte the same whatever the values are.
- **The whole request is one JSON file** passed with `--cli-input-json`, so no value goes through the AWS CLI's shorthand parser. No argument starts with `file://`, `http://` or `https://` other than that file: the AWS CLI reads such values as "load the value from there", and [version 1 even fetches http(s) URLs](https://docs.aws.amazon.com/cli/v1/userguide/cli-usage-parameters-file.html).
- **The request turns off everything that could keep data or bill twice:** no artifacts, no cache, no S3 logs, no retries, no debug session, and an idempotency token so a retried request can't start a second build.

### Settings

| What | Environment variable | `cloud.json` key | Default |
|---|---|---|---|
| CodeBuild project name | `GIT_BOUNCER_AWS_PROJECT` | `aws.project` | none (required) |
| S3 bucket | `GIT_BOUNCER_AWS_BUCKET` | `aws.bucket` | none (required) |
| Region | `GIT_BOUNCER_AWS_REGION` | `aws.region` | `AWS_REGION`, `AWS_DEFAULT_REGION`, then `aws configure get region` |

The AWS CLI's own settings (`AWS_PROFILE` and so on) work as usual, because git-bouncer runs `aws` exactly as you would.

## The config file

`~/.config/git-bouncer/cloud.json` (or `$XDG_CONFIG_HOME/git-bouncer/cloud.json`). Environment variables win over the file. Unknown keys are an error, so a typo is reported instead of silently ignored.

```json
{
  "gcp": { "project": "my-project-123", "region": "us-central1", "serviceAccount": "<name>@<project-id>.iam.gserviceaccount.com" },
  "aws": { "project": "git-bouncer", "region": "us-east-1", "bucket": "my-git-bouncer-uploads" }
}
```

## Security notes

**What is uploaded.** Only a copy of git-bouncer's own `sandbox/` folder, which is the same public code that's in this repository and the npm package. The copy refuses symlinks and anything that isn't a plain file, so nothing else on your machine can be pulled in. Nothing from the repository being checked is uploaded: the scanner fetches it inside the sandbox. On GCP the archive goes to `gs://<project-id>_cloudbuild/source/`; on AWS to `s3://BUCKET/git-bouncer/<run-id>/`. Both are deleted when the scan ends.

**What ends up in the logs and build records.** The build log contains the report: the repository URL and commit, and the findings, including file names and short excerpts from the scanned repository. The build record (visible in the console) contains the URL, the ref and the nonce. The nonce is single-use and only matters while that scan runs. How long logs are kept is up to your account:

- GCP: by default Cloud Build writes logs to Cloud Logging and to a Cloud Storage logs bucket; with a dedicated service account, to Cloud Logging only. See [Store and manage build logs](https://cloud.google.com/build/docs/securing-builds/store-manage-build-logs) for where they go and how long they stay.
- AWS: CloudWatch log groups never expire unless you set a retention period. The setup above sets 7 days.

**No credentials are passed to the scan.** The sandbox container gets no environment variables, no mounts and no Docker socket, just like a local scan. But the build machine around it does have credentials, so here is exactly where they are:

- *GCP:* Cloud Build serves the build's service-account credentials (through a metadata endpoint) on a Docker network named `cloudbuild`, which its own build steps are attached to. The sandbox is started on Docker's default `bridge` network (`--network=bridge`), not on `cloudbuild`. We could not verify from outside, without paying for test builds, whether the build machine's own metadata server at `169.254.169.254` can still be reached from the default network. **Assume it can.** That's the main reason to use a dedicated service account that can only write logs and read the upload.
- *AWS:* CodeBuild hands the service role's credentials to the build container through a local endpoint, whose address is in an environment variable (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`) that is never passed into the sandbox. **Assume the endpoint is reachable anyway**, and keep the role as small as the policy above.

Either way, the scanner never runs any of the repository's code (see [THREAT_MODEL.md](../THREAT_MODEL.md), T1), so nothing from the repository gets the chance to look for those credentials. The minimal role is the second line of defense.

**Network.** The sandbox needs internet access (git, the npm registry, OSV). Don't run these builds in a private pool or VPC that can reach your internal systems; the default Cloud Build pool and a CodeBuild project without a VPC are what this was designed for.

**Who can run builds.** Anyone who can start builds on the CodeBuild project can override its buildspec, which means running any command as its service role. The same goes for anyone who can create Cloud Build builds that run as the service account. That's one more reason to give the role and service account almost no permissions, and to use a project just for git-bouncer.

**Windows and gcloud.** On Windows, `gcloud` is a `.cmd` script. Node will only start those through `cmd.exe` ([CVE-2024-27980](https://nodejs.org/en/blog/vulnerability/april-2024-security-releases-2)), and `cmd.exe`'s argument quoting is exactly the kind of shell parsing git-bouncer avoids. So the GCP runtime says it isn't available on Windows. Use it from WSL. The AWS runtime works on Windows, because `aws` there is a real `.exe`.

## Known limitations

- **Not live-tested.** See the top of this page. The parts most likely to need fixing are the exact format of Cloud Build log lines (the `Step #1 - "scan": ` prefix that git-bouncer strips) and CloudWatch log paging.
- **No files come back.** `readFile()` always returns `null`, because the build machine is gone when the build ends. So when the scanned repository has no npm lockfile, the lockfile the sandbox generated and checked can't be copied into your local clone (see the handoff in [THREAT_MODEL.md](../THREAT_MODEL.md), T7).
- **Very large reports.** Cloud logging pipelines limit how long one log line can be. If a report line is too long and gets cut or split, git-bouncer doesn't find a complete report and treats the scan as failed. It fails closed rather than trusting a partial report.
- **Docker Hub rate limits.** The sandbox's base image comes from Docker Hub. Cloud Build checks Google's [`mirror.gcr.io` cache](https://cloud.google.com/build/docs/interacting-with-dockerhub-images) first. CodeBuild pulls from Docker Hub directly, from shared IP addresses, so you may hit Docker Hub's anonymous pull limit (`toomanyrequests`). If you do, change the `FROM` line in your copy of `sandbox/Dockerfile` to a mirror that serves the same image, keeping the `@sha256:` digest. Docker refuses an image whose digest doesn't match, so the pin still protects you.
- **BuildKit.** Both runtimes set `DOCKER_BUILDKIT=1` for the image build, so `docker build` fills in `TARGETARCH` and similar values. If your build image's Docker can't use BuildKit, that line is the one to change.

## What you might need to edit

| If... | Change |
|---|---|
| Scans run out of time on very large repositories | `GCP_LIMITS` in `src/runtimes/gcp.js`, or `AWS_LIMITS` in `src/runtimes/aws.js` |
| Your Cloud Build default machine is too small, or you want a faster one | add `options.machineType` in `buildCloudbuildConfig()` (it costs more per minute) |
| CodeBuild runs out of memory | a larger `computeType` on your project |
| You hit Docker Hub's rate limit | the `FROM` line in `sandbox/Dockerfile`, keeping the digest (see above) |
| Your organization requires a private worker pool or VPC | possible, but make sure it can't reach internal systems (see Network above) |

## More providers wanted

Azure (Container Instances or Pipelines), Fly.io Machines, Google Cloud Run jobs, a self-hosted runner, and others would all fit. A runtime is one module in `src/runtimes/` that exports the same five functions:

```js
{
  name,                       // 'gcp', 'aws', ...
  async available(),          // -> { ok, reason?, account? }: CLI installed, signed in, configured?
  async plan(scanRequest),    // -> { steps, files, notes }: runs nothing; this is what --dry-run prints
  async scan(scanRequest),    // -> { reportText, session }: runs exactly plan()'s steps
  async readFile(session, relPath, maxBytes), // -> contents, or null if the sandbox is gone
  async destroy(session),     // leave nothing running or billing
}
```

The rules from this page apply. Use argument arrays with no shell, and treat values as data in generated files. `plan()` stays pure. Tests use a fake `exec` and never touch a real cloud. And the docs say plainly whether you live-tested it. Please [open an issue](https://github.com/ylove/git-bouncer/issues) first to discuss the approach, then a pull request. If you **have** run one of these runtimes for real, a short issue saying what worked and what didn't is very welcome too.
