import os
import subprocess


def test_node_cli_bootstrap_failure_exit_code_nonzero():
    # Use an address expected to be unreachable.
    bad_ep = "tcp://10.255.255.1:1"

    # Use the installed console-script entrypoint so argument parsing and
    # SystemExit code propagation are correct.
    cli_exe = os.path.join(os.path.dirname(__file__), "..", ".venv", "bin", "decent-registry")
    cli_exe = os.path.abspath(cli_exe)
    assert os.path.exists(cli_exe)

    # Avoid -v because it's a global flag and must appear before the subcommand.
    cmd = [
        cli_exe,
        "node",
        "--host",
        "127.0.0.1",
        "--port",
        "0",
        "--bootstrap",
        bad_ep,
        "--run-seconds",
        "0.2",
    ]

    res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    assert res.returncode == 1, (
        f"expected exit code 1, got {res.returncode}\n"
        f"stdout:\n{res.stdout}\n"
        f"stderr:\n{res.stderr}\n"
    )
