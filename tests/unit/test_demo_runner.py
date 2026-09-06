from evidentia.demo.runner import is_allowed, run, scrub_env


def test_allowlisted_vector_passes():
    assert is_allowed(["doctor"]) is True
    assert is_allowed(["catalog", "list", "--tier", "A"]) is True


def test_raw_shell_and_arbitrary_verbs_refused():
    assert is_allowed(["collect", "okta"]) is False  # network verb excluded
    assert is_allowed(["mcp", "serve"]) is False
    assert is_allowed(["risk", "generate"]) is False
    assert is_allowed(["-c", "import os"]) is False  # no python -c
    assert is_allowed(["gap", "analyze", "--findings", "x"]) is False  # off-allowlist flag


def test_scrub_env_strips_credentials_and_forces_offline():
    env = scrub_env({"OPENAI_API_KEY": "sk-x", "AWS_SECRET_ACCESS_KEY": "y", "PATH": "/usr/bin"})
    assert "OPENAI_API_KEY" not in env and "AWS_SECRET_ACCESS_KEY" not in env
    assert env.get("EVIDENTIA_API_OFFLINE") == "1"
    assert "PATH" in env  # the allowlisted essentials survive


def test_run_refuses_off_allowlist_argv_without_exec():
    # A refused argv must never reach a subprocess — ``run`` returns exit 2
    # purely from the allowlist check, no ``evidentia`` spawn.
    assert run(["collect", "okta"]) == 2
    assert run(["-c", "import os"]) == 2
