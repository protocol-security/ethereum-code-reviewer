from ethereum_code_reviewer.commit_monitor import MonitoredRepository


def test_monitored_repository_from_url_preserves_branch_level_settings():
    repo = MonitoredRepository.from_url(
        "https://github.com/ethereum/go-ethereum",
        branch_configs=[
            {
                "branch_name": "master",
                "starting_commit_sha": "abc123",
                "hardfork_name": "cancun",
                "last_seen_head_sha": "def456",
            }
        ],
    )

    assert repo.full_name == "ethereum/go-ethereum"
    assert repo.branches == ["master"]
    assert repo.branch_configs[0].starting_commit_sha == "abc123"
    assert repo.branch_configs[0].hardfork_name == "cancun"
    assert repo.branch_configs[0].last_seen_head_sha == "def456"
def test_monitored_repository_from_url_builds_branch_configs_from_legacy_branch_list():
    repo = MonitoredRepository.from_url(
        "https://github.com/ethereum/go-ethereum",
        branches=["main", "develop"],
    )

    assert repo.branches == ["main", "develop"]
    assert repo.branch_configs[0].starting_commit_sha is None
    assert repo.branch_configs[1].hardfork_name is None
