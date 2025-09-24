"""
Setup configuration for code-reviewer package.
"""

from setuptools import setup, find_packages

setup(
    name="code-reviewer",
    version="0.1.0",
    description="GitHub Action for automated code review using LLMs (Anthropic / OpenAI)",
    author="",
    author_email="",
    packages=find_packages(),
    install_requires=[
        "anthropic>=0.7.0",
        "openai>=1.12.0",
        "PyGithub>=2.1.1",
        "packaging>=23.2"
    ],
    python_requires=">=3.8",
    license_files=["LICENSE"]
)
