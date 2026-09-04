#!/bin/sh
# MACO primary-worktree branch guard and previous-hook dispatcher.
#
# This is advisory defense in depth for ordinary Git commit and push commands.
# Git's explicit --no-verify and core.hooksPath overrides remain outside that
# boundary. The installer intentionally leaves core.hooksPath unset so managed
# child Git safety checks keep their current default-hooks contract.

hook_path=$0
hook_dir=${hook_path%/*}
if [ "$hook_dir" = "$hook_path" ]; then
    hook_dir=.
fi
hook_name=${hook_path##*/}

state_dir=$hook_dir/.maco-worktree-guard

refuse_state() {
    printf '%s\n' \
        "MACO worktree guard: refusing $1 because its installation state is invalid." \
        "Run 'maco worktree guard verify --repo <primary-repo>' and repair the installation." >&2
    exit 1
}

refuse_branch() {
    printf '%s\n' \
        "MACO worktree guard: refusing $1 from the primary worktree on agent branch '$2'." \
        "Agent branches must be committed and pushed from their linked worktrees." >&2
    exit 1
}

read_state() {
    state_value=
    state_extra=
    state_path=$state_dir/$1
    if [ ! -r "$state_path" ]; then
        refuse_state "$hook_name"
    fi
    {
        if ! IFS= read -r state_value; then
            refuse_state "$hook_name"
        fi
        if IFS= read -r state_extra || [ -n "$state_extra" ]; then
            refuse_state "$hook_name"
        fi
    } <"$state_path"
    if [ -z "$state_value" ]; then
        refuse_state "$hook_name"
    fi
}

read_unix_mode() {
    mode_candidate=
    if mode_candidate=$(stat -c '%a' "$1" 2>/dev/null); then
        case "$mode_candidate" in
            [0-7]|[0-7][0-7]|[0-7][0-7][0-7]|[0-7][0-7][0-7][0-7])
                mode_value=$mode_candidate
                return 0
                ;;
        esac
    fi
    if mode_candidate=$(stat -f '%Lp' "$1" 2>/dev/null); then
        case "$mode_candidate" in
            [0-7]|[0-7][0-7]|[0-7][0-7][0-7]|[0-7][0-7][0-7][0-7])
                mode_value=$mode_candidate
                return 0
                ;;
        esac
    fi
    return 1
}

case "$hook_name" in
    pre-commit)
        action=commit
        previous_state_name=pre-commit-previous
        ;;
    pre-merge-commit)
        action=commit
        previous_state_name=pre-merge-commit-previous
        ;;
    pre-push.human-authorship-previous)
        action=push
        previous_state_name=pre-push-previous
        ;;
    *)
        refuse_state "$hook_name"
        ;;
esac

read_state marker
if [ "$state_value" != maco-worktree-guard-v3 ]; then
    refuse_state "$action"
fi

previous=$hook_path.maco-worktree-guard-previous
if [ "$hook_name" = pre-push.human-authorship-previous ]; then
    read_state pre-push-target
    if [ "$state_value" != pre-push.human-authorship-previous ]; then
        refuse_state "$action"
    fi
fi
read_state "$previous_state_name"
previous_state=$state_value

actual_git_dir=$(git rev-parse --absolute-git-dir 2>/dev/null || :)
actual_common_dir=$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null || :)
if [ -z "$actual_git_dir" ] || [ -z "$actual_common_dir" ]; then
    refuse_state "$action"
fi

case "$previous_state" in
    absent)
        if [ -e "$previous" ] || [ -L "$previous" ]; then
            refuse_state "$action"
        fi
        ;;
    present:*)
        previous_binding=${previous_state#present:}
        case "$previous_binding" in
            *:*) ;;
            *) refuse_state "$action" ;;
        esac
        expected_previous_hash=${previous_binding%%:*}
        expected_previous_mode=${previous_binding#*:}
        case "$expected_previous_hash" in
            ''|*[!0-9a-f]*) refuse_state "$action" ;;
        esac
        case "${#expected_previous_hash}" in
            40|64) ;;
            *) refuse_state "$action" ;;
        esac
        case "$expected_previous_mode" in
            [0-7]|[0-7][0-7]|[0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;;
            *) refuse_state "$action" ;;
        esac
        if [ ! -f "$previous" ] || [ -L "$previous" ]; then
            refuse_state "$action"
        fi
        previous_hash=$(git hash-object --no-filters -- "$previous" 2>/dev/null || :)
        if [ "$previous_hash" != "$expected_previous_hash" ]; then
            refuse_state "$action"
        fi
        mode_value=
        if ! read_unix_mode "$previous"; then
            refuse_state "$action"
        fi
        if [ "$mode_value" != "$expected_previous_mode" ]; then
            refuse_state "$action"
        fi
        case "$expected_previous_mode" in
            *[1357]|*[1357][0-7]|*[1357][0-7][0-7])
                if [ ! -x "$previous" ]; then
                    refuse_state "$action"
                fi
                ;;
        esac
        ;;
    *)
        refuse_state "$action"
        ;;
esac

read_state common-dir
recorded_common_dir=$state_value
if [ "$actual_common_dir" != "$recorded_common_dir" ]; then
    refuse_state "$action"
fi

# The default hooks directory is shared by the primary and linked worktrees.
# Linked worktrees deliberately pass through: MACO's current managed-child Git
# boundary requires repository-local core.hooksPath to remain absent.
if [ "$actual_git_dir" != "$actual_common_dir" ]; then
    if [ -x "$previous" ]; then
        exec "$previous" "$@"
    fi
    exit 0
fi

read_state git-dir
if [ "$actual_git_dir" != "$state_value" ]; then
    refuse_state "$action"
fi

branch=$(git symbolic-ref --quiet --short HEAD 2>/dev/null || :)
case "$branch" in
    maco/*)
        refuse_branch "$action" "$branch"
        ;;
esac

# A custom-named branch checked out by any linked worktree is agent-owned too.
# Git's worktree HEAD files are the authoritative local branch association and
# require no MACO-private registry parsing in this dependency-free hook.
if [ -n "$branch" ]; then
    for linked_head in "$actual_common_dir"/worktrees/*/HEAD; do
        [ -r "$linked_head" ] || continue
        linked_ref=
        IFS= read -r linked_ref <"$linked_head" || :
        if [ "$linked_ref" = "ref: refs/heads/$branch" ]; then
            refuse_branch "$action" "$branch"
        fi
    done
fi

if [ -x "$previous" ]; then
    exec "$previous" "$@"
fi

exit 0
