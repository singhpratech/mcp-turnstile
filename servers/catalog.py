"""
catalog.py — realistic tool definitions for the benign servers.

The schemas here are deliberately written in the verbose style that real
production MCP servers ship (see the GitHub MCP server, ~27 tools / ~18k
tokens). Every parameter carries a prose description, enums are spelled out,
and common fields (owner/repo/pagination) are repeated on every tool exactly
as they are in practice. That repetition is the point: it is what the
token-tax benchmark measures, and what SEP-1576 proposed to deduplicate.

Nothing here is malicious. The poisoned/Unicode servers live in separate
files so the benign baseline stays clean.
"""

from __future__ import annotations

from harness.mcpkit import Tool

# Fields that appear on almost every tool in a real server, re-emitted in full
# every time (no $ref sharing in the 2025-11-25 schema style).
_OWNER = {
    "type": "string",
    "description": "The account owner of the repository. This is the username or "
    "organization name that owns the repository. Case-insensitive.",
}
_REPO = {
    "type": "string",
    "description": "The name of the repository without the .git extension. "
    "The name is not case sensitive.",
}
_PER_PAGE = {
    "type": "integer",
    "description": "The number of results per page (max 100). Use this together "
    "with the page parameter to paginate through large result sets.",
    "minimum": 1,
    "maximum": 100,
    "default": 30,
}
_PAGE = {
    "type": "integer",
    "description": "The page number of the results to fetch. Defaults to 1. "
    "Use with per_page to paginate through large result sets.",
    "minimum": 1,
    "default": 1,
}


def _schema(props: dict, required: list[str]) -> dict:
    return {
        "type": "object",
        "properties": props,
        "required": required,
        "additionalProperties": False,
        "$schema": "http://json-schema.org/draft-07/schema#",
    }


# A github-like catalog. 12 verbose tools — representative of a real server;
# the harness scales it to 24/48/72 via factors 2/4/6.
GITHUB_LIKE: list[Tool] = [
    Tool(
        "get_issue",
        "Gets the contents of a single issue within a repository, including its "
        "title, body, current state, assignees, labels, and metadata. Use this "
        "when you need the full detail of one specific issue by its number.",
        _schema(
            {
                "owner": _OWNER,
                "repo": _REPO,
                "issue_number": {
                    "type": "integer",
                    "description": "The number that identifies the issue within the "
                    "repository. This is the number shown in the issue URL and UI, "
                    "not the internal database id.",
                },
            },
            ["owner", "repo", "issue_number"],
        ),
    ),
    Tool(
        "create_issue",
        "Creates a new issue in the specified repository with a title and an "
        "optional body, assignees, labels, and milestone. Returns the created "
        "issue including its assigned number.",
        _schema(
            {
                "owner": _OWNER,
                "repo": _REPO,
                "title": {"type": "string", "description": "The title of the new issue."},
                "body": {
                    "type": "string",
                    "description": "The contents/body of the issue in GitHub-flavored "
                    "Markdown. Optional.",
                },
                "assignees": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Logins for users to assign to this issue. Optional.",
                },
                "labels": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Labels to associate with this issue. Optional.",
                },
                "milestone": {
                    "type": "integer",
                    "description": "The number of the milestone to associate this issue "
                    "with. Optional.",
                },
            },
            ["owner", "repo", "title"],
        ),
    ),
    Tool(
        "list_issues",
        "Lists issues in a repository, with optional filtering by state, labels, "
        "assignee, and sort order. Supports pagination. Returns an array of issue "
        "summaries.",
        _schema(
            {
                "owner": _OWNER,
                "repo": _REPO,
                "state": {
                    "type": "string",
                    "enum": ["open", "closed", "all"],
                    "description": "Filter issues by state. One of open, closed, or all. "
                    "Defaults to open.",
                    "default": "open",
                },
                "labels": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter issues by a list of comma-separated label names.",
                },
                "sort": {
                    "type": "string",
                    "enum": ["created", "updated", "comments"],
                    "description": "What to sort results by. One of created, updated, or "
                    "comments. Defaults to created.",
                    "default": "created",
                },
                "direction": {
                    "type": "string",
                    "enum": ["asc", "desc"],
                    "description": "The direction of the sort. One of asc or desc.",
                    "default": "desc",
                },
                "per_page": _PER_PAGE,
                "page": _PAGE,
            },
            ["owner", "repo"],
        ),
    ),
    Tool(
        "create_pull_request",
        "Creates a new pull request from a head branch into a base branch in the "
        "specified repository, with a title and optional body. Returns the created "
        "pull request including its number.",
        _schema(
            {
                "owner": _OWNER,
                "repo": _REPO,
                "title": {"type": "string", "description": "The title of the new pull request."},
                "head": {
                    "type": "string",
                    "description": "The name of the branch where your changes are "
                    "implemented. For cross-repository pull requests, use the format "
                    "username:branch.",
                },
                "base": {
                    "type": "string",
                    "description": "The name of the branch you want the changes pulled "
                    "into. This should be an existing branch in the repository.",
                },
                "body": {
                    "type": "string",
                    "description": "The contents of the pull request in Markdown. Optional.",
                },
                "draft": {
                    "type": "boolean",
                    "description": "Whether to create the pull request as a draft. Optional.",
                    "default": False,
                },
            },
            ["owner", "repo", "title", "head", "base"],
        ),
    ),
    Tool(
        "get_file_contents",
        "Gets the contents of a file or directory from a repository at a given path "
        "and optional git ref. Returns the decoded file contents for files, or a "
        "directory listing for directories.",
        _schema(
            {
                "owner": _OWNER,
                "repo": _REPO,
                "path": {
                    "type": "string",
                    "description": "The path to the file or directory within the "
                    "repository, relative to the repository root.",
                },
                "ref": {
                    "type": "string",
                    "description": "The name of the commit, branch, or tag to read from. "
                    "Defaults to the repository's default branch.",
                },
            },
            ["owner", "repo", "path"],
        ),
    ),
    Tool(
        "create_or_update_file",
        "Creates a new file or updates an existing file in a repository with the "
        "provided contents and commit message. For updates, the current file SHA "
        "must be supplied.",
        _schema(
            {
                "owner": _OWNER,
                "repo": _REPO,
                "path": {"type": "string", "description": "The path to the file to create or update."},
                "message": {"type": "string", "description": "The commit message for the change."},
                "content": {
                    "type": "string",
                    "description": "The new file content, provided as a UTF-8 string "
                    "(the server will base64-encode it).",
                },
                "branch": {
                    "type": "string",
                    "description": "The branch to commit to. Defaults to the default branch.",
                },
                "sha": {
                    "type": "string",
                    "description": "The blob SHA of the file being replaced. Required when "
                    "updating an existing file.",
                },
            },
            ["owner", "repo", "path", "message", "content"],
        ),
    ),
    Tool(
        "search_code",
        "Searches for code across repositories using GitHub code search syntax. "
        "Supports qualifiers such as repo:, path:, language:, and filename:. "
        "Returns matching code fragments with their file paths.",
        _schema(
            {
                "q": {
                    "type": "string",
                    "description": "The search query using GitHub code search syntax, "
                    "including any qualifiers such as repo:owner/name or language:python.",
                },
                "sort": {
                    "type": "string",
                    "enum": ["indexed"],
                    "description": "The sort field. Currently only indexed is supported.",
                },
                "order": {
                    "type": "string",
                    "enum": ["asc", "desc"],
                    "description": "The sort order, asc or desc.",
                },
                "per_page": _PER_PAGE,
                "page": _PAGE,
            },
            ["q"],
        ),
    ),
    Tool(
        "list_commits",
        "Lists commits on a repository branch, with optional filtering by author, "
        "path, and date range. Supports pagination. Returns commit summaries "
        "including SHA, author, and message.",
        _schema(
            {
                "owner": _OWNER,
                "repo": _REPO,
                "sha": {
                    "type": "string",
                    "description": "SHA or branch name to start listing commits from. "
                    "Defaults to the default branch.",
                },
                "path": {
                    "type": "string",
                    "description": "Only commits containing this file path will be returned.",
                },
                "author": {
                    "type": "string",
                    "description": "GitHub login or email address by which to filter commits.",
                },
                "per_page": _PER_PAGE,
                "page": _PAGE,
            },
            ["owner", "repo"],
        ),
    ),
    Tool(
        "merge_pull_request",
        "Merges a pull request into its base branch using the specified merge "
        "method. Optionally sets the commit title and message for the merge commit.",
        _schema(
            {
                "owner": _OWNER,
                "repo": _REPO,
                "pull_number": {
                    "type": "integer",
                    "description": "The number that identifies the pull request in the "
                    "repository.",
                },
                "merge_method": {
                    "type": "string",
                    "enum": ["merge", "squash", "rebase"],
                    "description": "The merge method to use. One of merge, squash, or "
                    "rebase. Defaults to merge.",
                    "default": "merge",
                },
                "commit_title": {"type": "string", "description": "Title for the merge commit."},
                "commit_message": {"type": "string", "description": "Extra detail for the merge commit."},
            },
            ["owner", "repo", "pull_number"],
        ),
    ),
    Tool(
        "add_issue_comment",
        "Adds a comment to an existing issue or pull request in the specified "
        "repository. Returns the created comment.",
        _schema(
            {
                "owner": _OWNER,
                "repo": _REPO,
                "issue_number": {
                    "type": "integer",
                    "description": "The number of the issue or pull request to comment on.",
                },
                "body": {"type": "string", "description": "The comment body in Markdown."},
            },
            ["owner", "repo", "issue_number", "body"],
        ),
    ),
    Tool(
        "create_branch",
        "Creates a new git branch in a repository from an optional source branch or "
        "commit SHA. Defaults to branching from the repository's default branch.",
        _schema(
            {
                "owner": _OWNER,
                "repo": _REPO,
                "branch": {"type": "string", "description": "The name for the new branch."},
                "from_branch": {
                    "type": "string",
                    "description": "The source branch or SHA to create the new branch from. "
                    "Defaults to the default branch.",
                },
            },
            ["owner", "repo", "branch"],
        ),
    ),
    Tool(
        "list_pull_requests",
        "Lists pull requests in a repository with optional filtering by state, head, "
        "and base branch, plus sort order. Supports pagination.",
        _schema(
            {
                "owner": _OWNER,
                "repo": _REPO,
                "state": {
                    "type": "string",
                    "enum": ["open", "closed", "all"],
                    "description": "Filter pull requests by state. Defaults to open.",
                    "default": "open",
                },
                "head": {"type": "string", "description": "Filter by head user/branch name."},
                "base": {"type": "string", "description": "Filter by base branch name."},
                "sort": {
                    "type": "string",
                    "enum": ["created", "updated", "popularity", "long-running"],
                    "description": "What to sort results by.",
                    "default": "created",
                },
                "direction": {
                    "type": "string",
                    "enum": ["asc", "desc"],
                    "description": "The direction of the sort.",
                },
                "per_page": _PER_PAGE,
                "page": _PAGE,
            },
            ["owner", "repo"],
        ),
    ),
]


def duplicate_catalog(base: list[Tool], factor: int, prefix: str) -> list[Tool]:
    """Return `factor` copies of the catalog with disambiguated names.

    Used to simulate connecting several servers / a large tool surface so the
    token tax can be shown at 12, 24, 48, ... tools without hand-writing them.
    """
    out: list[Tool] = []
    for i in range(factor):
        for t in base:
            name = t.name if i == 0 else f"{prefix}{i}_{t.name}"
            out.append(Tool(name, t.description, t.input_schema, t.annotations))
    return out
