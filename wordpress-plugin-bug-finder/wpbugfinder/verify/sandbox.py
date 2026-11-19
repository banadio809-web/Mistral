"""Dockerized WordPress sandbox for end-to-end PoC verification.

Spins up (or reuses) an isolated WordPress + MySQL stack using the docker
CLI (no SDK dependency), installs and activates the plugin under test,
creates the admin / subscriber accounts the agent logs in with, and exposes
helpers used while recording the verification video:

    with Sandbox(unique="run-abc") as sb:
        sb.wait_ready()
        sb.install_plugin(".../trunk", "sample-plugin")
        sb.activate("sample-plugin")
        page.goto(sb.url("/wp-login.php"))   # → recorded in the video
"""

import re
import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
import zipfile

WP_IMAGE = os.environ.get("WPBF_WP_IMAGE", "wordpress:php8.2-apache")
DB_IMAGE = os.environ.get("WPBF_DB_IMAGE", "mysql:8.0")
CLI_IMAGE = "wordpress:cli"
ADMIN_USER = os.environ.get("WPBF_ADMIN_USER", "wpbfadmin")
ADMIN_PASS = os.environ.get("WPBF_ADMIN_PASS", "wpbf-admin-pass-1")
SUB_USER = os.environ.get("WPBF_SUB_USER", "wpbfsubscriber")
SUB_PASS = os.environ.get("WPBF_SUB_PASS", "wpbf-sub-pass-1")
DB_NAME, DB_USER, DB_PASS = "wordpress", "wordpress", "wpbf-database-pass"


class SandboxError(RuntimeError):
    pass


def _run(args, check=True, capture=True, timeout=180):
    p = subprocess.run(args, check=False, capture_output=capture,
                       text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise SandboxError(
            f"docker command failed: {' '.join(args[:4])}…\n"
            f"stdout: {p.stdout[-2000:] if p.stdout else ''}\n"
            f"stderr: {p.stderr[-2000:] if p.stderr else ''}")
    return p


def _shquote(s: str) -> str:
    """Single-quote a token for the cli container's sh -c command."""
    return "'" + str(s).replace("'", "'\\''") + "'"


class Sandbox:
    """One disposable WordPress instance. Containers are named deterministically
    per `unique` so a run can be resumed with `reuse=True`."""

    def __init__(self, unique: str = "default", reuse: bool = True,
                 keep: bool = False):
        self.unique = re.sub(r"[^a-z0-9-]", "-", unique.lower())
        self.reuse = reuse
        self.keep = keep
        self.net = f"wpbfnet-{self.unique}"
        self.wp_name = f"wpbf-wp-{self.unique}"
        self.db_name = f"wpbf-db-{self.unique}"
        self.vol_html = f"wpbf-html-{self.unique}"
        self.port = None
        self._up = False

    # -- lifecycle ----------------------------------------------------------
    def docker_ok(self) -> bool:
        # Windows/Docker Desktop: `docker info` can take well over 15s on a
        # busy engine — probe with a generous timeout and one retry.
        for _ in range(2):
            try:
                _run(["docker", "info"], check=True, timeout=45)
                return True
            except Exception:
                time.sleep(2)
        return False

    def up(self):
        if not self.docker_ok():
            raise SandboxError(
                "Docker is not reachable — start Docker Desktop, or run "
                "with --sandbox off for headless (video-less) PoC checks.")
        _run(["docker", "network", "inspect", self.net], check=False)
        if _run(["docker", "network", "inspect", self.net],
                check=False).returncode != 0:
            _run(["docker", "network", "create", self.net])
        existing = _run(["docker", "ps", "-a", "--format", "{{.Names}}"],
                        check=False).stdout.split("\n")
        running = _run(["docker", "ps", "--format", "{{.Names}}"],
                       check=False).stdout.split("\n")

        if self.db_name not in existing:
            _run(["docker", "run", "-d", "--restart", "no",
                  "--name", self.db_name, "--network", self.net,
                  "-e", f"MYSQL_DATABASE={DB_NAME}",
                  "-e", f"MYSQL_USER={DB_USER}",
                  "-e", f"MYSQL_PASSWORD={DB_PASS}",
                  "-e", "MYSQL_ROOT_PASSWORD=root-wpbf",
                  DB_IMAGE])
        elif self.db_name not in running:
            _run(["docker", "start", self.db_name])

        if self.wp_name in existing:
            if self.wp_name not in running:
                _run(["docker", "start", self.wp_name])
        else:
            self.port = self._free_port()
            _run(["docker", "run", "-d", "--restart", "no",
                  "--name", self.wp_name, "--network", self.net,
                  "-p", f"{self.port}:80",
                  "-e", f"WORDPRESS_DB_HOST={self.db_name}",
                  "-e", f"WORDPRESS_DB_NAME={DB_NAME}",
                  "-e", f"WORDPRESS_DB_USER={DB_USER}",
                  "-e", f"WORDPRESS_DB_PASSWORD={DB_PASS}",
                  "-v", f"{self.vol_html}:/var/www/html",
                  WP_IMAGE])
        self._up = True
        self.wait_db()
        self.wait_ready()
        if not self.is_installed():
            self.install_wordpress()
        self.ensure_users()

    def down(self):
        if not self.keep:
            for name in (self.wp_name, self.db_name):
                _run(["docker", "rm", "-f", name], check=False)
        _run(["docker", "network", "rm", self.net], check=False)
        self._up = False

    def __enter__(self):
        self.up()
        return self

    def __exit__(self, *exc):
        self.down()

    @staticmethod
    def _free_port() -> int:
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    # -- readiness ----------------------------------------------------------
    def wait_db(self, timeout=300):
        t0 = time.time()
        while time.time() - t0 < timeout:
            p = _run(["docker", "exec", self.db_name, "mysqladmin", "ping",
                      "-uroot", "-proot-wpbf", "--silent"], check=False)
            if p.returncode == 0:
                return
            time.sleep(2)
        raise SandboxError("mysql never became ready")

    def wait_ready(self, timeout=300):
        """HTTP-readiness of the wp container; resolves the mapped port."""
        if self.port is None:
            raw = _run(["docker", "port", self.wp_name, "80"]).stdout.strip()
            self.port = int(raw.rsplit(":", 1)[1])
        t0 = time.time()
        last = None
        while time.time() - t0 < timeout:
            try:
                with urllib.request.urlopen(self.url("/wp-login.php"),
                                            timeout=5) as r:
                    if r.status == 200:
                        return
            except Exception as exc:   # noqa: PERF203 — retry loop
                last = exc
            time.sleep(2)
        raise SandboxError(f"wordpress container never became ready: {last}")

    def url(self, path: str = "/") -> str:
        return f"http://localhost:{self.port}{path}"

    # -- wp-cli -------------------------------------------------------------
    def _cli_docker(self, *args, check=False, timeout=120):
        """Run wp-cli in a throwaway wordpress:cli container attached to the
        sandbox network/volume.  DB envs are injected explicitly (the cli
        image defaults WORDPRESS_DB_HOST to 'mysql').  The wp command is
        passed as ONE sh -c string with --flag=value pairs: on Windows the
        python-subprocess → docker.exe → container arg chain silently
        separates --flag tokens from their values when passed as list items.
        """
        items = [str(a) for a in args]
        parts = ["wp"]
        i = 0
        while i < len(items):
            a = items[i]
            nxt = items[i + 1] if i + 1 < len(items) else None
            valueful = (a.startswith("--") and "=" not in a
                        and nxt is not None and not nxt.startswith("-"))
            if valueful:
                parts.append(f"{a}={_shquote(nxt)}")
                i += 2
            else:
                parts.append(a if (a.startswith("-") or "/" in a or
                                   a.startswith("--") or len(parts) > 1)
                             else _shquote(a))
                i += 1
        cmd = " ".join(parts)
        return _run(["docker", "run", "--rm", "--network", self.net,
                     "-v", f"{self.vol_html}:/var/www/html",
                     "--user", "33:33",
                     "-e", f"WORDPRESS_DB_HOST={self.db_name}",
                     "-e", f"WORDPRESS_DB_NAME={DB_NAME}",
                     "-e", f"WORDPRESS_DB_USER={DB_USER}",
                     "-e", f"WORDPRESS_DB_PASSWORD={DB_PASS}",
                     CLI_IMAGE, "sh", "-c", cmd],
                    check=check, timeout=timeout)

    def wpcli(self, *args, timeout=120) -> str:
        p = self._cli_docker(*args, check=False, timeout=timeout)
        out = (p.stdout or "") + (p.stderr or "")
        if p.returncode != 0:
            raise SandboxError(f"wpcli {' '.join(args[:4])} failed:\n{out[-2000:]}")
        return out.strip()

    def install_wordpress(self):
        self.wpcli("core", "install",
                   "--url", f"http://localhost:{self.port}",
                   "--title", "wpbf Verification Sandbox",
                   "--admin_user", ADMIN_USER, "--admin_password", ADMIN_PASS,
                   "--admin_email", "wpbfadmin@example.com", "--skip-email")

    def is_installed(self) -> bool:
        return self._cli_docker("core", "is-installed").returncode == 0

    def ensure_users(self):
        p = self._cli_docker("user", "get", SUB_USER, "--field=ID")
        if p.returncode != 0:
            self.wpcli("user", "create", SUB_USER,
                       "wpbfsubscriber@example.com", "--role=subscriber",
                       "--user_pass", SUB_PASS)

    # -- plugin management ---------------------------------------------------
    def install_plugin(self, source_dir: str, slug: str):
        """Zip the plugin source tree and install+activate it in the sandbox."""
        dest = f"/var/www/html/wp-content/plugins/{slug}"
        self.exec_sh(f"rm -rf {dest}")
        tmpzip = os.path.join(tempfile.gettempdir(), f"wpbf-{slug}.zip")
        with zipfile.ZipFile(tmpzip, "w", zipfile.ZIP_DEFLATED) as zf:
            base = os.path.dirname(os.path.abspath(source_dir))
            for dirpath, _dirnames, files in os.walk(source_dir):
                for fn in files:
                    full = os.path.join(dirpath, fn)
                    rel = os.path.join(
                        slug, os.path.relpath(full, source_dir))
                    zf.write(full, rel)
        inside_path = f"/var/www/html/wp-content/{slug}.zip"
        _run(["docker", "cp", tmpzip, f"{self.wp_name}:{inside_path}"])
        os.unlink(tmpzip)
        self.wpcli("plugin", "install",
                   f"/var/www/html/wp-content/{slug}.zip",
                   "--force", "--activate")
        self.exec_sh(f"rm -f /var/www/html/wp-content/{slug}.zip")

    def activate(self, slug: str):
        self.wpcli("plugin", "activate", slug)

    def exec_sh(self, script: str, timeout=30):
        return _run(["docker", "exec", self.wp_name, "sh", "-c", script],
                    check=False, timeout=timeout)

    def http_get(self, path: str, timeout=10):
        req = urllib.request.Request(self.url(path))
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, ""
        except Exception:
            return 0, ""

    def file_exists(self, container_path: str) -> bool:
        return self.exec_sh(f"[ -e '{container_path}' ] && echo yes || echo no"
                            ).stdout.strip() == "yes"

    def option_eq(self, option: str, value: str) -> bool:
        got = self.wpcli("option", "get", option, timeout=30)
        return got.strip() == value
