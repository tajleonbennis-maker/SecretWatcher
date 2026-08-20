from app.product_adapters import adapter_for, public_adapter_summary, public_paths_for


def test_deeptutor_adapter_is_verified_and_has_settings_route():
    adapter = adapter_for("DeepTutor")
    assert adapter is not None
    assert adapter.maturity == "verified"
    assert "/api/v1/settings" in public_paths_for("deeptutor")


def test_adapter_aliases_are_case_insensitive():
    assert adapter_for("OPEN-WEBUI").product == "Open WebUI"
    assert public_paths_for("unknown-product") == ()


def test_public_summary_does_not_expose_probe_paths_or_internal_evidence():
    summary = public_adapter_summary()
    assert any(item["product"] == "DeepTutor" for item in summary)
    assert all("public_paths" not in item and "evidence" not in item for item in summary)
