# TODO
# * optional dependencies
# * suggest updates
# * compare with vulnerability database

import shlex
import subprocess
import tomllib
import typing as t
from functools import cached_property
from pathlib import Path

import yaml
from packaging.requirements import Requirement, canonicalize_name
from packaging.version import Version
from pydantic import BaseModel, BeforeValidator
from pydantic_settings import CliPositionalArg

from pulp_sec.pypi import PackageInfo, Vulnerability


class TemplateConfig(BaseModel):
    plugin_default_branch: str = "main"
    latest_release_branch: str | None = None
    supported_release_branches: list[str] = []


class RepoInfo:
    """
    Lazily collect and cache info about the repository in the current dir.
    """

    def __init__(self):
        self._package_info_cache: dict[str, PackageInfo] = {}

    @cached_property
    def template_config(self) -> TemplateConfig:
        current_template_config = TemplateConfig.model_validate(
            yaml.safe_load(Path("template_config.yml").read_text())
        )
        default_branch = shlex.quote(current_template_config.plugin_default_branch)
        template_config_yml = subprocess.check_output(
            ["git", "show", f"upstream/{default_branch}:template_config.yml"]
        )
        return TemplateConfig.model_validate(yaml.safe_load(template_config_yml))

    @cached_property
    def supported_branches(self) -> list[str]:
        branches = set(self.template_config.supported_release_branches)
        if self.template_config.latest_release_branch is not None:
            branches.add(self.template_config.latest_release_branch)
        return [
            self.template_config.plugin_default_branch,
            *sorted(branches, key=Version, reverse=True),
        ]

    @cached_property
    def branches(self) -> dict[str, BranchInfo]:
        return {b: BranchInfo(self, b) for b in self.supported_branches}

    def package_info(self, name: str) -> PackageInfo:
        if name in self._package_info_cache:
            return self._package_info_cache[name]
        else:
            package_info = PackageInfo(name)
            self._package_info_cache[name] = package_info
            return package_info


def _strip_comment(req: str) -> str:
    return req.split("#", maxsplit=1)[0].strip()


class BranchInfo:
    """
    Lazily collect and cache info about a certain branch in the current repo.
    Do not change the working directory at all.
    """

    def __init__(self, repo_info: RepoInfo, branch: str):
        self._repo_info = repo_info
        self._branch = shlex.quote(branch)

    @cached_property
    def dependencies(self) -> list[Requirement]:
        try:
            # Try the modern approach.
            pyproject_toml = subprocess.check_output(
                ["git", "show", f"upstream/{self._branch}:pyproject.toml"]
            ).decode()
            pyproject = tomllib.loads(pyproject_toml)
            dependencies = pyproject["project"]["dependencies"]
        except subprocess.CalledProcessError, KeyError:
            # Fall back to old requirements.txt.
            requirements_txt = subprocess.check_output(
                ["git", "show", f"upstream/{self._branch}:requirements.txt"]
            ).decode()
            dependencies = [
                _strip_comment(line) for line in requirements_txt.splitlines()
            ]

        return [Requirement(line) for line in dependencies if line != ""]

    @cached_property
    def dependency_infos(self) -> list[DependencyInfo]:
        return [DependencyInfo(self._repo_info, dep) for dep in self.dependencies]


class DependencyInfo:
    def __init__(self, repo_info: RepoInfo, dependency: Requirement):
        self._repo_info = repo_info
        self._dependency = dependency
        self._package_info = repo_info.package_info(dependency.name)

    def __str__(self):
        return str(self._dependency)

    @cached_property
    def target_version(self) -> Version:
        return next(
            v
            for v in reversed(self._package_info.versions)
            if v in self._dependency.specifier
        )

    @property
    def name(self) -> str:
        return canonicalize_name(self._dependency.name)

    @property
    def vulnerable(self) -> bool:
        # Merely a proxy here.
        return self._package_info.releases[self.target_version].vulnerable

    @property
    def vulnerabilities(self) -> list[Vulnerability]:
        # Merely a proxy here.
        return self._package_info.releases[self.target_version].vulnerabilities


class Bad(BaseModel):
    """Check project for a bad apple dependency."""

    dependency: CliPositionalArg[
        t.Annotated[str, BeforeValidator(canonicalize_name)] | None
    ] = None

    def cli_cmd(self) -> None:
        repo_info = RepoInfo()
        for branch in repo_info.supported_branches:
            print(f"[{branch}]:")
            branch_info = repo_info.branches[branch]
            for dep in branch_info.dependency_infos:
                if self.dependency is None or self.dependency == dep.name:
                    vuln = "V" if dep.vulnerable else " "
                    print(f" [{vuln}]  {dep} => {dep.target_version}")
                    if dep.vulnerable:
                        v_ids = ", ".join(v.id for v in dep.vulnerabilities)
                        print(f"  ⤷    {v_ids}")
