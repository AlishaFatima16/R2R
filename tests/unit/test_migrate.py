from pipeline.load.migrate import checksum, migration_files


def test_checksum_ignores_line_endings(tmp_path):
    lf = tmp_path / "001_a.sql"
    crlf = tmp_path / "002_b.sql"
    lf.write_bytes(b"SELECT 1;\nSELECT 2;\n")
    crlf.write_bytes(b"SELECT 1;\r\nSELECT 2;\r\n")
    assert checksum(lf) == checksum(crlf)


def test_checksum_detects_real_change(tmp_path):
    a = tmp_path / "001_a.sql"
    b = tmp_path / "002_b.sql"
    a.write_text("SELECT 1;\n")
    b.write_text("SELECT 2;\n")
    assert checksum(a) != checksum(b)


def test_migration_files_are_ordered_and_filtered(tmp_path):
    for name in ["010_c.sql", "002_b.sql", "001_a.sql", "notes.sql", "readme.md"]:
        (tmp_path / name).write_text("-- x\n")
    assert [p.name for p in migration_files(tmp_path)] == [
        "001_a.sql",
        "002_b.sql",
        "010_c.sql",
    ]