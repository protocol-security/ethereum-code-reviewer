import pytest

import ethereum_code_reviewer.spec_context as sc


FUSAKA_META = """---
title: Hardfork Meta - Fusaka
---
## Specification
### Included EIPs
#### Core EIPs
* [EIP-7594](./eip-7594.md): PeerDAS
* [EIP-7825](./eip-7825.md): transaction gas limit cap
#### Other EIPs
* [EIP-7892](./eip-7892.md): blob parameter only hardforks
## Rationale
This section mentions EIP-9999 which must NOT be treated as included.
"""

# A draft meta lists "EIPs Scheduled for Inclusion" plus sibling sections that
# must be excluded (especially "Declined for Inclusion").
DRAFT_META = """### EIPs Scheduled for Inclusion
* [EIP-7708](./eip-7708.md): a
* [EIP-7732](./eip-7732.md): b
### Considered for Inclusion
* [EIP-2222](./eip-2222.md): maybe
### Declined for Inclusion
* [EIP-1111](./eip-1111.md): no
"""

META_INDEX_HTML = """
<tr><td class="eipnum"><a href="/EIPS/eip-7607">7607</a></td><td class="title">Hardfork Meta - Fusaka</td></tr>
<tr><td class="eipnum"><a href="/EIPS/eip-7600">7600</a></td><td class="title">Hardfork Meta - Pectra</td></tr>
<tr><td class="eipnum"><a href="/EIPS/eip-7568">7568</a></td><td class="title">Hardfork Meta Backfill - Berlin to Shapella</td></tr>
"""


def _routes():
    return {
        sc.META_INDEX_URL: META_INDEX_HTML,
        sc.EIPS_RAW.format(n=7607): FUSAKA_META,
        sc.EIPS_RAW.format(n=7594): "EIP-7594 body",
        sc.EIPS_RAW.format(n=7825): "EIP-7825 body",
        sc.EIPS_RAW.format(n=7892): "EIP-7892 body",
        sc.EIPS_RAW.format(n=4844): "EIP-4844 body",
    }


def _install_fake_net(monkeypatch, tmp_path, calls=None, routes=None):
    routes = routes or _routes()
    monkeypatch.setenv("REVIEWER_CACHE_DIR", str(tmp_path / "cache"))

    def fake_get(url):
        if calls is not None:
            calls.append(url)
        return routes.get(url)

    monkeypatch.setattr(sc, "_get", fake_get)
    sc.fork_meta_index.cache_clear()


def test_extract_eip_numbers_dedup_order():
    assert sc.extract_eip_numbers("touches EIP-4844, eip 1559, and EIP-4844 again") == [4844, 1559]
    assert sc.extract_eip_numbers("") == []


def test_parse_included_eips_final_excludes_prose_refs():
    assert sc.parse_included_eips(FUSAKA_META) == {7594, 7825, 7892}


def test_parse_included_eips_draft_excludes_declined_and_considered():
    # Only the "Scheduled for Inclusion" section, not Considered/Declined siblings.
    assert sc.parse_included_eips(DRAFT_META) == {7708, 7732}


def test_resolve_meta_eip_via_index_and_aliases(monkeypatch, tmp_path):
    _install_fake_net(monkeypatch, tmp_path)
    assert sc.resolve_meta_eip("fusaka") == 7607
    assert sc.resolve_meta_eip("Fusaka") == 7607
    assert sc.resolve_meta_eip("fulu") == 7607      # consensus-layer alias
    assert sc.resolve_meta_eip("osaka") == 7607      # execution-layer alias
    assert sc.resolve_meta_eip("pectra") == 7600
    assert sc.resolve_meta_eip("not-a-fork") is None


def test_build_review_context_fork_plus_diff_eips(monkeypatch, tmp_path):
    _install_fake_net(monkeypatch, tmp_path)
    result = sc.build_review_context(
        "agents/execution-layer/AGENTS.md",
        "the diff references EIP-4844",
        hardfork_name="fusaka",
        strict=True,
    )
    m = result.manifest
    assert m["meta_eip"] == 7607
    assert m["expected_eips"] == [7594, 7825, 7892]
    assert 4844 in m["fetched_eips"]  # diff-referenced EIP fetched too
    assert m["missing_eips"] == []
    assert result.scope_description == "hardfork:fusaka"
    # diff-referenced EIP is ordered first (most relevant)
    assert result.selected_docs[0] == "EIPS/eip-4844.md"


def test_build_review_context_strict_raises_on_missing(monkeypatch, tmp_path):
    routes = _routes()
    del routes[sc.EIPS_RAW.format(n=7825)]  # one expected EIP unfetchable
    _install_fake_net(monkeypatch, tmp_path, routes=routes)
    with pytest.raises(sc.SpecFetchError):
        sc.build_review_context(
            "agents/execution-layer/AGENTS.md", "", hardfork_name="fusaka", strict=True
        )


def test_build_review_context_unavailable_degrades(monkeypatch, tmp_path):
    monkeypatch.setenv("REVIEWER_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(sc, "_get", lambda url: None)
    sc.fork_meta_index.cache_clear()
    result = sc.build_review_context("agents/execution-layer/AGENTS.md", "no eip refs here")
    assert result.scope_description == "spec-fetch-unavailable"
    assert result.text == ""


def test_cache_delta_only_new_eips_downloaded(monkeypatch, tmp_path):
    calls = []
    _install_fake_net(monkeypatch, tmp_path, calls=calls)
    first = sc.build_review_context("agents/execution-layer/AGENTS.md", "", hardfork_name="fusaka")
    assert first.manifest["downloaded"] == 3
    assert first.manifest["cache_hits"] == 0

    second = sc.build_review_context("agents/execution-layer/AGENTS.md", "", hardfork_name="fusaka")
    assert second.manifest["downloaded"] == 0
    assert second.manifest["cache_hits"] == 3
