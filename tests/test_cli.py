"""
Tests for Aegis command-line interface.
"""

from pathlib import Path
from aegis.cli import main


def test_cli_help(capsys):
    try:
        main(["--help"])
    except SystemExit as e:
        assert e.code == 0
    captured = capsys.readouterr()
    assert "Aegis Vault" in captured.out


def test_cli_encrypt_decrypt_inspect(tmp_path: Path, capsys):
    in_file = tmp_path / "cli_test.txt"
    in_file.write_text("Command-line encryption test payload", encoding="utf-8")

    # Encrypt
    enc_ret = main(["encrypt", str(in_file), "-p", "TestCliPassword123"])
    assert enc_ret == 0

    aegis_file = in_file.with_name("cli_test.txt.aegis")
    assert aegis_file.exists()

    # Inspect
    insp_ret = main(["inspect", str(aegis_file), "--json"])
    assert insp_ret == 0
    captured = capsys.readouterr()
    assert '"version": 1' in captured.out

    # Decrypt
    dec_file = tmp_path / "cli_restored.txt"
    dec_ret = main(["decrypt", str(aegis_file), "-o", str(dec_file), "-p", "TestCliPassword123"])
    assert dec_ret == 0
    assert dec_file.read_text(encoding="utf-8") == "Command-line encryption test payload"


def test_cli_xray(capsys):
    ret = main(["xray", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    assert '"num_rounds": 10' in captured.out


def test_cli_strength(capsys):
    ret = main(["strength", "MySecurePass123!@#", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    assert '"entropy_bits"' in captured.out


def test_cli_avalanche(capsys):
    ret = main(["avalanche", "--bit", "0", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    assert '"sac_satisfied"' in captured.out
