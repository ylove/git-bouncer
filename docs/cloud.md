# Cloud runtimes: GCP Cloud Build and AWS CodeBuild

> **Not live-tested by the maintainer, because it costs money.**
>
> These runtimes are built and unit-tested: every generated build file and every command line has a test, and no test talks to a real cloud. The exact `docker run` command lines they generate have also been run against a locally built sandbox image. But nobody has run them against a real Google Cloud project or AWS account. Treat them as a careful starting point for your own setup, read what they would do with `--dry-run` first, and please [open an issue](https://github.com/ylove/git-bouncer/issues) if something doesn't work.

Most people should use the local sandbox (Docker or Podman) or the Codespaces fallback. The cloud runtimes are for people who would rather run the check in their own cloud account, signed in with `gcloud` or `aws`. They are opt-in only: git-bouncer never picks them unless you pass `--runtime gcp` or `--runtime aws`.

## What they do

Both runtimes do what a local scan does, on a throwaway machine in your account:

1. Copy git-bouncer's own `sandbox/` folder (the Dockerfile and the scanner) to a private temporary folder on your machine.
2. Upload that copy to a bucket in your account, under a prefix used only by this run. **Nothing else from your machine is uploaded, and nothing from the repository being checked.** The scanner clones the repository itself, inside the sandbox.
3. Start a build that:
   1. builds the sandbox image from that folder;
   2. runs the **metadata canary**: a few lines of git-bouncer's own JavaScript, in a sandbox container with the scan's own settings. The build fails if the container can get credentials from the cloud's metadata or credential endpoints;
   3. runs the scanner in a sandbox container. It uses the same hardening flags as a local scan, defined in one place (`sandboxFlags()` in `src/runtimes/container.js`): no Linux capabilities, a read-only filesystem, an unprivileged user, an init process, size-limited `noexec` scratch space, process, memory and CPU limits, and **no credentials, mounts or environment variables**. The report's secret nonce reaches the scanner on stdin, never as an argument.
4. Wait for the build, then read its log. The report sits in the log between two marker lines that contain the nonce your machine chose for this scan.
5. Clean up: delete everything the run uploaded, and the temporary folder. If git-bouncer is interrupted (Ctrl-C, a closed terminal, a timeout), it cancels the build and deletes the upload before it exits. That works even if the build's ID was never printed: the build is found by the run's tag (GCP) or by its source location (AWS).

The cloud machines are deleted when the build ends, so there is nothing to inspect afterwards, and `--keep` has no effect with these runtimes.

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

Each scan builds the sandbox image from scratch (there is no cache to reuse between builds), runs the canary (a few seconds), then scans. Expect a few minutes of build time per scan, more for repositories with many dependencies. To cap the bill:

- Every build has its own time limit: **30 minutes** to run and **15 minutes** to get started. The limits hold even if git-bouncer itself crashes or loses its network connection, so the worst case is one build running to its limit.
- AWS builds never retry automatically (`autoRetryLimitOverride: 0`), so a failed scan is never quietly run and billed again.
- Set a [budget alert](https://cloud.google.com/billing/docs/how-to/budgets) on GCP or an [AWS Budget](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html) before you start.

## Google Cloud (Cloud Build)

### One-time setup

You need the [Google Cloud CLI](https://cloud.google.com/sdk/docs/install), a project with billing enabled, and three things git-bouncer insists on: **a dedicated service account, a bucket of its own, and (strongly recommended) a project used for nothing else.** In a project of its own, a build gone wrong has nothing else to reach.

```sh
PROJECT=<project-id>              # a project just for git-bouncer
BUCKET=<bucket-name>              # for example: $PROJECT-git-bouncer (no dots)
gcloud config set project "$PROJECT"
gcloud services enable cloudbuild.googleapis.com

# The bucket for uploads. Anything a crash leaves behind is deleted after a day.
gcloud storage buckets create "gs://${BUCKET}" --project="$PROJECT" --uniform-bucket-level-access
gcloud storage buckets update "gs://${BUCKET}" --lifecycle-file=lifecycle.json

# The service account the build runs as. It can write its build log and read the uploads. Nothing else.
gcloud iam service-accounts create git-bouncer-scan --display-name="git-bouncer scans" --project="$PROJECT"
SA="git-bouncer-scan@${PROJECT}.iam.gserviceaccount.com"
gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:$SA" --role=roles/logging.logWriter
gcloud storage buckets add-iam-policy-binding "gs://${BUCKET}" --member="serviceAccount:$SA" --role=roles/storage.objectViewer

# Allow yourself to start builds that run as it. If you are signed in to gcloud as a service
# account rather than a person, use --member="serviceAccount:<that account's email>" instead.
gcloud iam service-accounts add-iam-policy-binding "$SA" --member="user:$(gcloud config get-value account)" --role=roles/iam.serviceAccountUser
```

`lifecycle.json`:

```json
{ "rule": [ { "action": { "type": "Delete" }, "condition": { "age": 1, "matchesPrefix": ["git-bouncer/"] } } ] }
```

Then put the service account and bucket in your settings (see [Settings](#settings)).

Why it's this strict:

- **No dedicated service account, no scan.** Without one, the build runs as the project's default Cloud Build identity. Depending on the project's age, that is either the legacy Cloud Build service account, which can write to Cloud Storage and Artifact Registry, or the Compute Engine default service account, which in many projects is an Editor. If an exploit ever got code running inside the sandbox and reached that identity's token, it could poison other builds or images. git-bouncer refuses to scan until you configure an identity that can't do any of that.
- **Its own bucket, not `<project>_cloudbuild`.** That shared staging bucket keeps the source archive of every `gcloud builds submit` ever run in the project, and gcloud never deletes them. Read access to it can mean read access to private code. With a bucket of its own, the scan identity can read only git-bouncer's uploads. git-bouncer also checks, before every scan, that the bucket belongs to your project (it compares the bucket's project number with yours). Bucket names are global, and gcloud doesn't make that check for a staging location you choose.
- With your own service account, Cloud Build requires logs to go to Cloud Logging or to a bucket you own. git-bouncer uses Cloud Logging (`logging: CLOUD_LOGGING_ONLY`). See [Configure user-specified service accounts](https://cloud.google.com/build/docs/securing-builds/configure-user-specified-service-accounts).

**Your own permissions.** Owner or Editor of the dedicated project is simplest. The minimum is:

- Cloud Build Editor (`roles/cloudbuild.builds.editor`), to start, describe, list and cancel builds.
- Logs Viewer (`roles/logging.viewer`), to read the build log. The log, and the report in it, is in Cloud Logging. Without this role you'd have a finished build whose report you can't read.
- Storage Admin (`roles/storage.admin`) on the git-bouncer bucket only. It covers uploading and deleting, plus reading the bucket's metadata, which both gcloud and the ownership check need.
- Service Account User on the scan service account (the last command above).
- Read access to the project itself (`resourcemanager.projects.get`, for example the Browser role `roles/browser`), for the project-number check.

**Progress.** While the build runs, git-bouncer shows its status (queued, working), checked every 10 seconds. It reads the log once the build has finished. It doesn't stream the log, because the GA `gcloud builds log --stream` only streams logs kept in Cloud Storage, and these are kept in Cloud Logging. To watch a build live, open the build in the Cloud console, or run `gcloud beta builds log --stream <build-id>`.

### What runs

```text
gcloud builds submit <temp-dir>/source --config=<temp-dir>/cloudbuild.yaml --gcs-source-staging-dir=gs://<bucket>/git-bouncer/<run-id> --project=<project> --async --format=value(id) --user-output-enabled --quiet
gcloud builds describe <build-id> --project=<project> --format=json --user-output-enabled --quiet          # every 10 seconds until done
gcloud builds log <build-id> --project=<project> --user-output-enabled --quiet
gcloud storage rm gs://<bucket>/git-bouncer/<run-id>/** --project=<project> --user-output-enabled --quiet
gcloud builds list --ongoing --filter=tags:git-bouncer-run-<run-id> --format=value(id) --limit=10 ...      # only if interrupted before the build ID was seen
gcloud builds cancel <build-id> ...                                                                       # only if interrupted while the build runs
```

Before these, `available()` checks that you're signed in, reads the project's number (`gcloud projects describe`), and compares it with the bucket's (`gcloud storage buckets describe --raw`). `--region=<region>` is added to the `builds` commands when you set a region. `<run-id>` is derived one-way from the scan's nonce, so the nonce itself never appears in a bucket listing or a tag.

The generated `cloudbuild.yaml` has three steps, all run by Google's docker builder image, pinned by digest:

- **The image build and the canary** are plain argument lists for `docker`, with no shell.
- **The scan** has to get the nonce onto the scanner's stdin, and Cloud Build steps have no stdin. So it runs bash with one **constant** script: `printf '%s\n' "$GIT_BOUNCER_NONCE" | docker "$@"`. In the file it is written with `$$`, Cloud Build's escape for a literal `$`. The nonce comes from the step's environment. Everything else (the `docker run` flags, the URL, the ref) arrives as `"$@"`, which bash passes on without parsing. This is the only `$` in the file, and a test makes sure of that. Cloud Build expands `$NAME` anywhere in a build file, and the URL and ref can't contain a `$` (they're validated twice before they get here).

Why it's built this way:

- **A generated file rather than `--substitutions`.** Substitutions would keep the build file fixed, but the values would then go through gcloud's `KEY=VALUE,KEY=VALUE` flag parser, and a fixed file can't leave out `--ref` when there isn't one. Instead every value is written as a quoted string by one small serializer.
- **The report comes from `gcloud builds log` after the build has finished.** Builds that log to Cloud Logging can take a moment to become readable, so git-bouncer asks again a few times.
- **`--user-output-enabled` and a few environment settings** keep your own gcloud configuration from changing what git-bouncer reads. `core/user_output_enabled=false` would make gcloud print nothing, so a build that started would look like one that didn't. `accessibility/screen_reader` makes gcloud delete `---> ` from every log line, and `core/log_http` prints raw HTTP traffic.

### Settings

| What | Environment variable | `cloud.json` key | Default |
|---|---|---|---|
| Service account (email) | `GIT_BOUNCER_GCP_SERVICE_ACCOUNT` | `gcp.serviceAccount` | none: **required** |
| Bucket for uploads | `GIT_BOUNCER_GCP_BUCKET` | `gcp.bucket` | none: **required** |
| Project | `GIT_BOUNCER_GCP_PROJECT` | `gcp.project` | `gcloud config get-value project` |
| Region | `GIT_BOUNCER_GCP_REGION` | `gcp.region` | gcloud's `builds/region` setting, else `global` |

Only standard project IDs (`my-project-123`) are accepted, not the older domain-scoped kind (`example.com:project`). The sandbox asks for 2 CPUs (`--cpus 2`), which the default Cloud Build machine (`e2-standard-2`, see the pricing page) has.

## AWS (CodeBuild)

### One-time setup

You need [version 2 of the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html), signed in (`aws configure` or `aws sso login`). Version 1 is refused: it fetches any parameter value that starts with `http://` or `https://`, and it lacks `--no-cli-auto-prompt`. You then create three things, all in **one region**: an S3 bucket for the upload, an IAM role for the build, and a CodeBuild project. An AWS account used only for git-bouncer is the safest place for them. Replace `REGION`, `ACCOUNT_ID` and `BUCKET` below.

**1. An S3 bucket** for the uploaded sandbox folder. Use a new, private bucket just for this (new buckets block public access by default). Bucket names with dots aren't accepted. git-bouncer deletes each upload after the scan; a lifecycle rule cleans up anything a crash left behind:

```sh
aws s3api create-bucket --bucket BUCKET --region REGION --create-bucket-configuration LocationConstraint=REGION   # leave out --create-bucket-configuration in us-east-1
aws s3api put-bucket-lifecycle-configuration --bucket BUCKET --lifecycle-configuration file://lifecycle.json
```

`lifecycle.json`:

```json
{ "Rules": [ { "ID": "expire-git-bouncer-uploads", "Status": "Enabled", "Filter": { "Prefix": "git-bouncer/" }, "Expiration": { "Days": 1 } } ] }
```

S3 bucket names are global, so nothing in a bucket name says whose it is. If the name you configured ever isn't yours (a typo, or a bucket you deleted that someone else then claimed), its owner could swap the uploaded scanner for their own code. CodeBuild would then run it in privileged mode, with your role. So the bucket has to be owned by your account, and that is checked three times:

- git-bouncer asks S3 before every scan: `head-bucket --expected-bucket-owner <your account>`.
- Every upload and delete carries `--expected-bucket-owner`, so S3 refuses it for any other owner.
- The policies below only allow the bucket in your account (`s3:ResourceAccount`).

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
      "Resource": "arn:aws:s3:::BUCKET/git-bouncer/*",
      "Condition": { "StringEquals": { "s3:ResourceAccount": "ACCOUNT_ID" } }
    },
    {
      "Sid": "FindTheUpload",
      "Effect": "Allow",
      "Action": ["s3:ListBucket", "s3:GetBucketAcl", "s3:GetBucketLocation"],
      "Resource": "arn:aws:s3:::BUCKET",
      "Condition": { "StringEquals": { "s3:ResourceAccount": "ACCOUNT_ID" } }
    }
  ]
}
```

```sh
aws iam create-role --role-name git-bouncer-codebuild --assume-role-policy-document file://trust.json
aws iam put-role-policy --role-name git-bouncer-codebuild --policy-name git-bouncer-codebuild --policy-document file://role-policy.json
```

Give it nothing else. In particular, no permission to read secrets, parameters or other buckets.

**3. A CodeBuild project** (`project.json`). Privileged mode is required: CodeBuild only runs Docker inside a build in privileged mode. Use `BUILD_GENERAL1_MEDIUM` or larger: the sandbox may use up to 4 GB of memory and 2 CPUs, and `SMALL` (4 GiB) leaves too little for Docker itself ([compute types](https://docs.aws.amazon.com/codebuild/latest/userguide/build-env-ref-compute-types.html)). Don't give it a VPC, environment variables or secrets: git-bouncer supplies everything per build.

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
      "Action": ["codebuild:BatchGetProjects", "codebuild:StartBuild", "codebuild:BatchGetBuilds", "codebuild:StopBuild", "codebuild:ListBuildsForProject"],
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
      "Resource": "arn:aws:s3:::BUCKET/git-bouncer/*",
      "Condition": { "StringEquals": { "s3:ResourceAccount": "ACCOUNT_ID" } }
    },
    {
      "Sid": "CheckAndListTheBucket",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::BUCKET",
      "Condition": { "StringEquals": { "s3:ResourceAccount": "ACCOUNT_ID" } }
    }
  ]
}
```

(`head-bucket` and `list-objects-v2` both need `s3:ListBucket`.) git-bouncer overrides the project's buildspec, source and privileged mode on every build. If your organization blocks those overrides with IAM condition keys or service control policies, StartBuild is refused and git-bouncer shows the error.

### What runs

```text
aws s3api put-object --bucket=BUCKET --key=git-bouncer/<run-id>/<file> --body=<temp-dir>/source/<file> --expected-bucket-owner=<account-id> ...   # once per file
aws codebuild start-build --cli-input-json=file://<temp-dir>/start-build.json --region=REGION --output=json --no-cli-auto-prompt
aws codebuild batch-get-builds --ids=<build-id> ...                                    # every 10 seconds until done
aws logs get-log-events --log-group-name=<log-group> --log-stream-name=<log-stream> --start-from-head ...   # then --next-token=<token> to the end
aws s3api list-objects-v2 --bucket=BUCKET --prefix=git-bouncer/<run-id>/ --expected-bucket-owner=<account-id> ...
aws s3api delete-objects --bucket=BUCKET --delete=<the keys it listed> --expected-bucket-owner=<account-id> ...
aws codebuild list-builds-for-project ... / batch-get-builds --ids <ids>               # only if interrupted before the build ID was seen
aws codebuild stop-build --id=<build-id> ...                                           # only if interrupted while the build runs
```

Before these, `available()` checks that you're signed in (`sts get-caller-identity`), that your account owns the bucket (`s3api head-bucket --expected-bucket-owner`), and that the project exists. Every call carries `--region` and `--no-cli-auto-prompt`. `<run-id>` is derived one-way from the scan's nonce, so the nonce itself never appears in a bucket listing.

The buildspec runs, in order:

1. two `iptables` rules that block, for containers, the build host's instance metadata (`169.254.169.254`) and the CodeBuild credentials endpoint (`169.254.170.2`);
2. the image build;
3. the canary, which fails the build if either address answers at all;
4. the scan, with the nonce piped in by `printf`, a shell builtin, so it is never any process's argument.

Why it's built this way:

- **The source goes through S3** because CodeBuild has no "upload this folder" option. The alternatives were to put the scanner inside the buildspec or an environment variable (size limits, and shell commands would have to unpack it), or to have the build download git-bouncer from GitHub (then the cloud would run whatever GitHub serves, not the exact files you installed).
- **The low-level `s3api` commands, one file at a time,** because only they accept `--expected-bucket-owner`. The high-level `aws s3 cp` and `aws s3 rm` don't. Cleanup lists what is actually there (an interrupted upload may be partial) and deletes exactly that.
- **The shell text never contains a value.** CodeBuild runs buildspec commands through a shell; there is no way to pass an argument list. So the commands are fixed text, and the URL, ref and nonce arrive as environment variables that the commands only use inside double quotes (`"$GIT_BOUNCER_URL"`). A shell does not re-read the value of a double-quoted variable as shell syntax, so a value can't turn into a second command. A unit test checks that the buildspec is byte-for-byte the same whatever the values are.
- **The whole request is one JSON file** passed with `--cli-input-json`, so no value goes through the AWS CLI's shorthand parser. No argument starts with `file://`, `http://` or `https://` other than that file: the AWS CLI reads such values as "load the value from there", and [version 1 even fetches http(s) URLs](https://docs.aws.amazon.com/cli/v1/userguide/cli-usage-parameters-file.html).
- **The request turns off everything that could keep data or bill twice:** no artifacts, no cache, no S3 logs, no retries, no debug session, and an idempotency token so a retried request can't start a second build.
- **The log is read to its real end.** CloudWatch can return an empty page while more events are on the way. Only getting back the same token you sent means the end of the stream. If the report isn't complete yet, git-bouncer waits and continues from where it stopped.

### Settings

| What | Environment variable | `cloud.json` key | Default |
|---|---|---|---|
| CodeBuild project name | `GIT_BOUNCER_AWS_PROJECT` | `aws.project` | none: **required** |
| S3 bucket | `GIT_BOUNCER_AWS_BUCKET` | `aws.bucket` | none: **required** |
| Region | `GIT_BOUNCER_AWS_REGION` | `aws.region` | `AWS_REGION`, `AWS_DEFAULT_REGION`, then `aws configure get region` |

The AWS CLI's own settings (`AWS_PROFILE` and so on) work as usual, because git-bouncer runs `aws` exactly as you would (with `AWS_PAGER` empty, so it never opens a pager).

## The config file

`~/.config/git-bouncer/cloud.json` (or `$XDG_CONFIG_HOME/git-bouncer/cloud.json`). Environment variables win over the file. Unknown keys are an error, so a typo is reported instead of silently ignored.

```json
{
  "gcp": { "project": "my-project-123", "region": "us-central1", "bucket": "my-project-123-git-bouncer", "serviceAccount": "<name>@<project-id>.iam.gserviceaccount.com" },
  "aws": { "project": "git-bouncer", "region": "us-east-1", "bucket": "my-git-bouncer-uploads" }
}
```

## Security notes

**Why the sandbox needs these defenses even though no repo code runs.** The scanner never runs any of the repository's code (see [THREAT_MODEL.md](../THREAT_MODEL.md), T1). But git, npm's lockfile and tarball handling, and osv-scanner all parse bytes the repository's author controls, inside the sandbox. Parsers have bugs: git has had clone-time exploits (CVE-2024-32002, CVE-2025-48384; T5). The defenses below are for that case, a parser bug or a container escape, and they are not optional. That's why the minimal identities are required, not merely recommended.

**What is uploaded.** Only a copy of git-bouncer's own `sandbox/` folder, which is the same public code that's in this repository and the npm package. The copy refuses symlinks and anything that isn't a plain file, so nothing else on your machine can be pulled in. Nothing from the repository being checked is uploaded: the scanner fetches it inside the sandbox. On GCP the upload goes to `gs://<bucket>/git-bouncer/<run-id>/`, and on AWS to `s3://BUCKET/git-bouncer/<run-id>/`. Both are deleted when the scan ends, and the lifecycle rules catch anything a crash left behind.

**The nonce.** The report is trusted only between two lines containing a random nonce chosen on your machine, which is what stops anything inside the sandbox from printing a fake "all clear". The nonce is never a command-line argument inside the sandbox: arguments are readable by every process there (`/proc/<pid>/cmdline`). It reaches the scanner on stdin. Outside the sandbox it's in the build's configuration (GCP: the scan step's environment; AWS: an environment variable of the build), which only your account can see, and it's useless once that scan has finished.

**What ends up in logs, build records and audit trails.** The build log contains the report: the repository URL and commit, and the findings, including file names and short excerpts from the scanned repository. The build record (visible in the console) contains the URL, the ref and the nonce. Copies can also end up, with their own retention, in:

- *AWS CloudTrail:* the StartBuild event can include `environmentVariablesOverride`, that is the URL, ref and nonce in plain text.
- *Google Cloud Audit Logs:* Cloud Build's Admin Activity audit log can include the CreateBuild request, with the steps' arguments and environment.
- *Organization-level log sinks,* if your organization has them, which may copy build logs (and so reports) to another project or account.

How long build logs are kept is up to your account. GCP: these builds log to Cloud Logging, and that bucket's retention applies ([Store and manage build logs](https://cloud.google.com/build/docs/securing-builds/store-manage-build-logs)). AWS: CloudWatch log groups never expire unless you set a retention period; the setup above sets 7 days.

**Credentials.** The sandbox container gets no environment variables, no mounts and no Docker socket, just like a local scan. But the build machine around it does have credentials. Here is exactly where they are, and what stops the sandbox from using them:

- *GCP:* Cloud Build serves the build's service-account credentials on a Docker network named `cloudbuild`, which its own build steps are attached to. The sandbox is started on Docker's default `bridge` network, not on `cloudbuild`. The build machine's own metadata server is at `169.254.169.254`, and on Google's VMs that address is also the DNS resolver, so it is almost certainly reachable from the sandbox. What matters is whether it hands out a token there. Instead of guessing, **every build runs the metadata canary**: it asks for a token from inside a sandbox container with the scan's own settings, and the build fails if it gets one. The scan identity is still a dedicated service account that can only write logs and read the uploads, in case the canary ever misses something.
- *AWS:* CodeBuild hands the role's credentials to the build container through an endpoint at the fixed address `169.254.170.2`. The secret part is the path, which is in the build container's environment variable `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` and never passed into the sandbox. The build host's instance metadata service is at `169.254.169.254`. Both addresses are blocked for containers with `iptables` before any container starts (the buildspec runs as root, in the network namespace whose firewall Docker uses), and **the canary checks that neither answers**. The rules are `/32`s, so a link-local DNS resolver keeps working.
- *AWS, privileged mode:* CodeBuild only runs Docker in privileged mode. Its curated images also start their Docker daemon listening, without authentication, on `tcp://127.0.0.1:2375` inside the build container. Any way for the sandbox to reach the build container's loopback, such as host networking, would be a complete escape to the role. That's why the sandbox is always on its own `bridge` network, and a test checks that `--network host` never appears.

**Network.** The sandbox needs internet access (git, the npm registry, OSV). Don't run these builds in a private pool or VPC that can reach your internal systems. The default Cloud Build pool, and a CodeBuild project without a VPC, are what this was designed for.

**Who can run builds.** Anyone who can start builds on the CodeBuild project can override its buildspec, which means running any command as its role. The same goes for anyone who can create Cloud Build builds that run as the scan service account. That's one more reason to give the role and the service account almost no permissions, and to keep them in a project or account used only for git-bouncer.

**Windows and gcloud.** On Windows, `gcloud` is a `.cmd` script. Node will only start those through `cmd.exe` ([CVE-2024-27980](https://nodejs.org/en/blog/vulnerability/april-2024-security-releases-2)), and `cmd.exe`'s argument parsing is exactly the kind of shell parsing git-bouncer avoids. So the GCP runtime says it isn't available on Windows. Use it from WSL. The AWS runtime works on Windows, because `aws` there is a real `.exe`. git-bouncer finds both programs only in absolute `PATH` folders, so a folder like `.` or `node_modules/.bin` can never supply them.

## Known limitations

- **Not live-tested.** See the top of this page. The parts most likely to need fixing are the exact format of Cloud Build log lines (the `Step #2 - "scan": ` prefix that git-bouncer strips) and CloudWatch log paging.
- **No files come back.** `readFile()` always returns `null`, because the build machine is gone when the build ends. So when the scanned repository has no npm lockfile, the lockfile the sandbox generated and checked can't be copied into your local clone (see the handoff in [THREAT_MODEL.md](../THREAT_MODEL.md), T7).
- **Very large reports fail closed.** The report is one line of JSON, and cloud logging pipelines cap how long one log entry can be (Cloud Logging and CloudWatch both have per-entry limits, far below the 8 MB a local scan allows). If a report line is cut or split, git-bouncer doesn't find a complete report and the result is **INCOMPLETE**. A hostile repository can force that on purpose, for example by producing lots of findings. It can't force a pass.
- **Docker Hub rate limits.** The sandbox's base image comes from Docker Hub. Cloud Build checks Google's [`mirror.gcr.io` cache](https://cloud.google.com/build/docs/interacting-with-dockerhub-images) first. CodeBuild pulls from Docker Hub directly, from shared IP addresses, so you may hit Docker Hub's anonymous pull limit (`toomanyrequests`). If you do, change the `FROM` lines in your copy of `sandbox/Dockerfile` to a mirror that serves the same image, keeping the `@sha256:` digest. Docker refuses an image whose digest doesn't match, so the pin still protects you.
- **BuildKit and iptables.** Both runtimes set `DOCKER_BUILDKIT=1` so `docker build` fills in `TARGETARCH`. On AWS the buildspec needs `iptables` and Docker's `DOCKER-USER` chain. Both are part of CodeBuild's curated images. If they're missing, the build fails before anything runs, which is the safe way to fail.
- **The builder image is pinned by hand.** `DOCKER_BUILDER` in `src/runtimes/gcp.js` names `gcr.io/cloud-builders/docker` by digest. Dependabot can't update a digest inside JavaScript, so the comment there says how to refresh it.

## What you might need to edit

| If... | Change |
|---|---|
| Scans run out of time on very large repositories | `GCP_LIMITS` in `src/runtimes/gcp.js`, or `AWS_LIMITS` in `src/runtimes/aws.js` |
| You want a faster Cloud Build machine | add `options.machineType` in `buildCloudbuildConfig()` (it costs more per minute; it needs at least 2 CPUs) |
| CodeBuild runs out of memory | a larger `computeType` on your project |
| You hit Docker Hub's rate limit | the `FROM` lines in `sandbox/Dockerfile`, keeping the digest (see above) |
| The docker builder image needs updating | `DOCKER_BUILDER` in `src/runtimes/gcp.js` (see its comment) |
| Your organization requires a private worker pool or VPC | possible, but make sure it can't reach internal systems (see Network above) |

## More providers wanted

Azure (Container Instances or Pipelines), Fly.io Machines, Google Cloud Run jobs, a self-hosted runner, and others would all fit. A runtime is one module in `src/runtimes/` with the same shape as the others, which is what `src/commands/check.js` calls:

```js
{
  name,                        // 'gcp', 'aws', ...
  async available(),           // -> { ok, reason?, account? }: CLI installed, signed in, configured?
  async plan(scanRequest),     // -> { steps, files, notes }: runs nothing; this is what --dry-run prints
  async scan({ url, ref, nonce, onSession, ... }),  // -> { reportText, session }: runs exactly plan()'s steps;
                               //    calls onSession(session) BEFORE creating anything, so an interrupt can clean up
  async readFile(session, relPath), // -> contents, or null if the sandbox is gone
  async destroy(session),      // leave nothing running or billing; must work while scan() is still running
  describe(),                  // one line for "using ..."
}
```

The rules from this page apply:

- Use argument arrays and no shell, except a constant one where the platform gives you no choice. Values stay data in generated files.
- The nonce reaches the sandbox only on stdin.
- The hardening comes from `sandboxFlags()`.
- `plan()` stays pure.
- Tests use a fake `exec` and never touch a real cloud.
- The docs say plainly whether you live-tested it.

Please [open an issue](https://github.com/ylove/git-bouncer/issues) first to discuss the approach, then a pull request. If you **have** run one of these runtimes for real, a short issue saying what worked and what didn't is very welcome too.
