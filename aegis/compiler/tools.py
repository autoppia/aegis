"""Composable tool registry for state gatherers.

Self-contained API clients using only Python stdlib (urllib, json, subprocess).
Generated state.py files import from this module to fetch runtime data.

Usage in generated state.py:
    from aegis.compiler.tools import aws, runpod, github, contabo

    def get_state() -> dict:
        instances = aws.list_ec2_instances()
        return {"instance_count": len(instances)}
"""

from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.request
from typing import Any


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only)
# ---------------------------------------------------------------------------

def _http_get(url: str, headers: dict | None = None, timeout: int = 15) -> Any:
    """GET request, return parsed JSON or None on failure."""
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError):
        return None


def _http_post(url: str, data: dict, headers: dict | None = None,
               timeout: int = 15, form: bool = False) -> Any:
    """POST request (JSON or form), return parsed JSON or None."""
    h = dict(headers or {})
    if form:
        body = urllib.parse.urlencode(data).encode("utf-8")
        h.setdefault("Content-Type", "application/x-www-form-urlencoded")
    else:
        body = json.dumps(data).encode("utf-8")
        h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=body, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError):
        return None


import urllib.parse  # noqa: E402 (keep imports grouped by section)


# ---------------------------------------------------------------------------
# AWS — uses boto3 via subprocess (aws cli) for zero-dep
# ---------------------------------------------------------------------------

class _AWS:
    """AWS tools via AWS CLI (subprocess).

    Requires: aws CLI installed and configured, OR
    env vars AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION.
    """

    @staticmethod
    def _cli(service: str, command: str, args: list[str] | None = None,
             region: str | None = None) -> Any:
        """Run `aws <service> <command>` and return parsed JSON."""
        cmd = ["aws", service, command, "--output", "json"]
        if region:
            cmd.extend(["--region", region])
        if args:
            cmd.extend(args)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                return None
            return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, FileNotFoundError,
                json.JSONDecodeError, OSError):
            return None

    def list_ec2_instances(self, region: str | None = None) -> list[dict]:
        """List EC2 instances with name, state, type, IPs."""
        data = self._cli("ec2", "describe-instances", region=region)
        if not data:
            return []
        instances = []
        for reservation in data.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                name = ""
                for tag in inst.get("Tags", []):
                    if tag.get("Key") == "Name":
                        name = tag.get("Value", "")
                instances.append({
                    "id": inst.get("InstanceId"),
                    "name": name,
                    "state": inst.get("State", {}).get("Name"),
                    "type": inst.get("InstanceType"),
                    "public_ip": inst.get("PublicIpAddress"),
                    "private_ip": inst.get("PrivateIpAddress"),
                    "launch_time": inst.get("LaunchTime"),
                })
        return instances

    def list_s3_buckets(self) -> list[dict]:
        """List S3 buckets."""
        data = self._cli("s3api", "list-buckets")
        if not data:
            return []
        return [
            {"name": b.get("Name"), "created": b.get("CreationDate")}
            for b in data.get("Buckets", [])
        ]

    def get_monthly_costs(self, months: int = 1) -> dict:
        """Get AWS costs using Cost Explorer CLI."""
        import datetime
        end = datetime.date.today().replace(day=1)
        start = end
        for _ in range(months):
            start = (start - datetime.timedelta(days=1)).replace(day=1)
        data = self._cli("ce", "get-cost-and-usage", [
            "--time-period", f"Start={start.isoformat()},End={end.isoformat()}",
            "--granularity", "MONTHLY",
            "--metrics", "BlendedCost",
        ])
        return data if data else {}

    def get_cost_by_service(self, months: int = 1) -> dict:
        """Get cost breakdown by service."""
        import datetime
        end = datetime.date.today().replace(day=1)
        start = end
        for _ in range(months):
            start = (start - datetime.timedelta(days=1)).replace(day=1)
        data = self._cli("ce", "get-cost-and-usage", [
            "--time-period", f"Start={start.isoformat()},End={end.isoformat()}",
            "--granularity", "MONTHLY",
            "--metrics", "BlendedCost",
            "--group-by", "Type=DIMENSION,Key=SERVICE",
        ])
        return data if data else {}


# ---------------------------------------------------------------------------
# RunPod — GraphQL API
# ---------------------------------------------------------------------------

class _RunPod:
    """RunPod tools via GraphQL API.

    Requires: RUNPOD_API_KEY env var.
    """

    API_URL = "https://api.runpod.io/graphql"

    @staticmethod
    def _query(query: str, variables: dict | None = None) -> dict:
        api_key = os.environ.get("RUNPOD_API_KEY", "")
        if not api_key:
            return {}
        url = f"{_RunPod.API_URL}?api_key={api_key}"
        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables
        result = _http_post(url, payload)
        if isinstance(result, dict):
            return result.get("data", {})
        return {}

    def list_pods(self) -> list[dict]:
        """List all RunPod pods."""
        data = self._query("""
            query { myself { pods {
                id name desiredStatus imageName machineId
                machine { gpuDisplayName }
                gpuCount vcpuCount memoryInGb volumeInGb
                runtime { uptimeInSeconds gpus { gpuUtilPercent } }
            } } }
        """)
        return data.get("myself", {}).get("pods", [])

    def get_pod(self, pod_id: str) -> dict:
        """Get pod details."""
        data = self._query("""
            query Pod($podId: String!) { pod(input: {podId: $podId}) {
                id name desiredStatus imageName
                gpuCount vcpuCount memoryInGb volumeInGb
                runtime { uptimeInSeconds gpus { gpuUtilPercent } }
            } }
        """, {"podId": pod_id})
        return data.get("pod", {})

    def get_balance(self) -> dict:
        """Get balance and spend rate."""
        data = self._query("""
            query { myself {
                clientBalance currentSpendPerHr
                machineQuota referralEarned
            } }
        """)
        return data.get("myself", {})

    def list_gpu_types(self) -> list[dict]:
        """List available GPU types with pricing."""
        data = self._query("""
            query { gpuTypes {
                id displayName memoryInGb
                secureCloud communityCloud
                lowestPrice { minimumBidPrice uninterruptablePrice }
            } }
        """)
        return data.get("gpuTypes", [])


# ---------------------------------------------------------------------------
# GitHub — REST API
# ---------------------------------------------------------------------------

class _GitHub:
    """GitHub tools via REST API.

    Requires: GITHUB_TOKEN env var.
    """

    API_URL = "https://api.github.com"

    @staticmethod
    def _headers() -> dict:
        token = os.environ.get("GITHUB_TOKEN", "")
        h = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            h["Authorization"] = f"token {token}"
        return h

    def _get(self, endpoint: str, params: dict | None = None) -> Any:
        url = f"{self.API_URL}{endpoint}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        return _http_get(url, headers=self._headers())

    def list_repos(self, per_page: int = 30, visibility: str | None = None) -> list[dict]:
        """List user's repos."""
        params: dict[str, Any] = {"per_page": per_page, "sort": "updated"}
        if visibility:
            params["visibility"] = visibility
        result = self._get("/user/repos", params)
        return result if isinstance(result, list) else []

    def list_org_repos(self, org: str, per_page: int = 30) -> list[dict]:
        """List org repos."""
        result = self._get(f"/orgs/{org}/repos", {"per_page": per_page, "sort": "updated"})
        return result if isinstance(result, list) else []

    def get_repo(self, owner: str, repo: str) -> dict:
        """Get repo details."""
        result = self._get(f"/repos/{owner}/{repo}")
        return result if isinstance(result, dict) else {}

    def list_issues(self, owner: str, repo: str, state: str = "open",
                    per_page: int = 30) -> list[dict]:
        """List issues (excludes PRs)."""
        result = self._get(f"/repos/{owner}/{repo}/issues",
                           {"state": state, "per_page": per_page})
        if not isinstance(result, list):
            return []
        return [i for i in result if "pull_request" not in i]

    def list_prs(self, owner: str, repo: str, state: str = "open",
                 per_page: int = 30) -> list[dict]:
        """List pull requests."""
        result = self._get(f"/repos/{owner}/{repo}/pulls",
                           {"state": state, "per_page": per_page})
        return result if isinstance(result, list) else []

    def list_workflow_runs(self, owner: str, repo: str,
                           status: str | None = None, per_page: int = 10) -> list[dict]:
        """List GitHub Actions workflow runs."""
        params: dict[str, Any] = {"per_page": per_page}
        if status:
            params["status"] = status
        result = self._get(f"/repos/{owner}/{repo}/actions/runs", params)
        if isinstance(result, dict):
            return result.get("workflow_runs", [])
        return []

    def list_branches(self, owner: str, repo: str, per_page: int = 30) -> list[dict]:
        """List branches."""
        result = self._get(f"/repos/{owner}/{repo}/branches", {"per_page": per_page})
        return result if isinstance(result, list) else []


# ---------------------------------------------------------------------------
# Contabo — REST API with OAuth2
# ---------------------------------------------------------------------------

class _Contabo:
    """Contabo tools via REST API with OAuth2 auth.

    Requires env vars: CONTABO_CLIENT_ID, CONTABO_CLIENT_SECRET,
                       CONTABO_API_USER, CONTABO_API_PASSWORD.
    """

    AUTH_URL = "https://auth.contabo.com/auth/realms/contabo/protocol/openid-connect/token"
    API_URL = "https://api.contabo.com/v1"

    _token: str | None = None
    _token_expires: float = 0

    @classmethod
    def _get_token(cls) -> str | None:
        import time
        import uuid
        if cls._token and time.time() < cls._token_expires - 60:
            return cls._token
        data = {
            "client_id": os.environ.get("CONTABO_CLIENT_ID", ""),
            "client_secret": os.environ.get("CONTABO_CLIENT_SECRET", ""),
            "username": os.environ.get("CONTABO_API_USER", ""),
            "password": os.environ.get("CONTABO_API_PASSWORD", ""),
            "grant_type": "password",
        }
        if not all(data.values()):
            return None
        result = _http_post(cls.AUTH_URL, data, form=True)
        if not result or "access_token" not in result:
            return None
        cls._token = result["access_token"]
        cls._token_expires = time.time() + result.get("expires_in", 300)
        return cls._token

    def _get(self, endpoint: str, params: dict | None = None) -> Any:
        import uuid
        token = self._get_token()
        if not token:
            return None
        url = f"{self.API_URL}{endpoint}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        headers = {
            "Authorization": f"Bearer {token}",
            "x-request-id": str(uuid.uuid4()),
        }
        return _http_get(url, headers=headers)

    def list_instances(self, status: str | None = None) -> list[dict]:
        """List Contabo instances."""
        params: dict[str, Any] = {"size": 100}
        if status:
            params["status"] = status
        result = self._get("/compute/instances", params)
        if isinstance(result, dict):
            return result.get("data", [])
        return result if isinstance(result, list) else []

    def get_instance(self, instance_id: int) -> dict:
        """Get instance details."""
        result = self._get(f"/compute/instances/{instance_id}")
        if isinstance(result, dict):
            return result.get("data", result)
        return {}


# ---------------------------------------------------------------------------
# Kubernetes — kubectl subprocess
# ---------------------------------------------------------------------------

class _Kubernetes:
    """Kubernetes tools via kubectl subprocess.

    Requires: kubectl installed and configured.
    """

    @staticmethod
    def _kubectl(resource: str, namespace: str | None = None) -> list[dict]:
        cmd = ["kubectl", "get", resource, "-o", "json"]
        if namespace:
            cmd.extend(["-n", namespace])
        else:
            cmd.append("--all-namespaces")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode != 0:
                return []
            data = json.loads(result.stdout)
            return data.get("items", [])
        except (subprocess.TimeoutExpired, FileNotFoundError,
                json.JSONDecodeError, OSError):
            return []

    def list_pods(self, namespace: str | None = None) -> list[dict]:
        return self._kubectl("pods", namespace)

    def list_namespaces(self) -> list[dict]:
        return self._kubectl("namespaces")

    def list_deployments(self, namespace: str | None = None) -> list[dict]:
        return self._kubectl("deployments", namespace)


# ---------------------------------------------------------------------------
# Public singletons
# ---------------------------------------------------------------------------

aws = _AWS()
runpod = _RunPod()
github = _GitHub()
contabo = _Contabo()
kubernetes = _Kubernetes()


# ---------------------------------------------------------------------------
# Tool catalog — used by the compiler to tell the LLM what's available
# ---------------------------------------------------------------------------

TOOL_CATALOG = """
## Available tools for state gathering

Import: `from aegis.compiler.tools import aws, runpod, github, contabo, kubernetes`

These are self-contained API clients. All functions return empty list/dict on
failure (never raise). Use them in get_state() to fetch runtime data.

### aws (requires aws CLI or AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY env vars)
- `aws.list_ec2_instances(region=None) -> list[dict]` — Each dict has: id, name, state, type, public_ip, private_ip, launch_time
- `aws.list_s3_buckets() -> list[dict]` — Each dict has: name, created
- `aws.get_monthly_costs(months=1) -> dict` — Cost Explorer data
- `aws.get_cost_by_service(months=1) -> dict` — Cost breakdown by service

### runpod (requires RUNPOD_API_KEY env var)
- `runpod.list_pods() -> list[dict]` — Each dict has: id, name, desiredStatus, gpuCount, etc.
- `runpod.get_pod(pod_id) -> dict` — Pod details
- `runpod.get_balance() -> dict` — Has: clientBalance, currentSpendPerHr
- `runpod.list_gpu_types() -> list[dict]` — GPU types with pricing

### github (requires GITHUB_TOKEN env var)
- `github.list_repos(per_page=30, visibility=None) -> list[dict]` — User's repos
- `github.list_org_repos(org, per_page=30) -> list[dict]` — Org repos
- `github.get_repo(owner, repo) -> dict` — Full repo details (has open_issues_count, etc.)
- `github.list_issues(owner, repo, state="open") -> list[dict]` — Issues (excludes PRs)
- `github.list_prs(owner, repo, state="open") -> list[dict]` — Pull requests
- `github.list_workflow_runs(owner, repo, status=None) -> list[dict]` — CI runs
- `github.list_branches(owner, repo) -> list[dict]` — Branches

### contabo (requires CONTABO_CLIENT_ID, CONTABO_CLIENT_SECRET, CONTABO_API_USER, CONTABO_API_PASSWORD)
- `contabo.list_instances(status=None) -> list[dict]` — Contabo VPS instances
- `contabo.get_instance(instance_id) -> dict` — Instance details

### kubernetes (requires kubectl installed and configured)
- `kubernetes.list_pods(namespace=None) -> list[dict]` — K8s pods
- `kubernetes.list_namespaces() -> list[dict]` — Namespaces
- `kubernetes.list_deployments(namespace=None) -> list[dict]` — Deployments
"""
