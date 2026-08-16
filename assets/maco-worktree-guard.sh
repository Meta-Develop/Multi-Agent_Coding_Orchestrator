#!/bin/sh
# MACO worktree guard and hook dispatcher.
#
# This is deliberately an advisory defense-in-depth check for interactive Git
# use by humans or workers. MACO's orchestrated Git commands keep
# core.hooksPath=/dev/null so untrusted repository hooks cannot affect trusted
# orchestration; this script must not, and cannot, weaken or replace that
# isolation. Git's standard --no-verify/core.hooksPath mechanisms remain the
# advisory boundary's explicit limitation; this dispatcher adds no environment
# variable that a worker could set accidentally or routinely.

hook_path=$0
hook_dir=${hook_path%/*}
if [ "$hook_dir" = "$hook_path" ]; then
    hook_dir=.
fi
hook_name=${hook_path##*/}
case "$hook_name" in
    *.human-authorship-previous)
        # The human-authorship installer may move this composing dispatcher to
        # its exact backup suffix. Retain MACO commit/push checks in that slot.
        hook_name=${hook_name%.human-authorship-previous}
        ;;
esac
guard_root=${hook_dir%/hooks}

guard_refusal() {
    printf '%s\n' \
        "MACO worktree guard: refusing $1" \
        "$2" \
        "This guard is advisory defense-in-depth for interactive Git use." >&2
    exit 1
}

guard_state_refusal() {
    printf '%s\n' \
        "MACO worktree guard: refusing $1" \
        "$2" >&2
    exit 1
}

read_guard_value() {
    guard_value=
    if [ -r "$guard_root/$1" ]; then
        IFS= read -r guard_value <"$guard_root/$1" || :
    fi
}

guard_branch_identity() {
    action=$1

    actual_git_dir=$(git rev-parse --absolute-git-dir 2>/dev/null || :)
    actual_common_dir=$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null || :)
    if [ -z "$actual_git_dir" ] || [ -z "$actual_common_dir" ]; then
        guard_state_refusal \
            "$action because Git worktree identity cannot be resolved." \
            "Run 'maco worktree guard verify --repo <worktree>' and reinstall if needed."
    fi

    read_guard_value git-dir
    recorded_git_dir=$guard_value
    read_guard_value common-dir
    recorded_common_dir=$guard_value
    if [ -z "$recorded_git_dir" ] || [ "$actual_git_dir" != "$recorded_git_dir" ]; then
        guard_state_refusal \
            "$action because the Git directory identity changed." \
            "This hook belongs to a different worktree or its guard state was altered."
    fi
    if [ -z "$recorded_common_dir" ] || [ "$actual_common_dir" != "$recorded_common_dir" ]; then
        guard_state_refusal \
            "$action because the Git common-directory identity changed." \
            "This hook belongs to a different repository or its guard state was altered."
    fi

    current_branch=$(git symbolic-ref --quiet --short HEAD 2>/dev/null || :)
    read_guard_value mode
    guard_mode=$guard_value

    case "$guard_mode" in
        managed)
            if [ "$actual_git_dir" = "$actual_common_dir" ]; then
                guard_state_refusal \
                    "$action because a managed guard resolved to the primary worktree." \
                    "Run 'maco worktree guard verify --repo <worktree>' and reinstall if needed."
            fi
            read_guard_value expected-branch
            expected_branch=$guard_value
            if [ -z "$expected_branch" ]; then
                guard_state_refusal \
                    "$action because managed guard branch state is missing." \
                    "Run 'maco worktree guard verify --repo <worktree>' and reinstall if needed."
            fi
            ;;
        primary)
            if [ "$actual_git_dir" != "$actual_common_dir" ]; then
                guard_state_refusal \
                    "$action because a primary guard resolved to a linked worktree." \
                    "Run 'maco worktree guard verify --repo <worktree>' and reinstall if needed."
            fi
            ;;
        *)
            printf '%s\n' \
                "MACO worktree guard: invalid installation mode; refusing $action." \
                "Run 'maco worktree guard verify --repo <primary-repo>' and reinstall if needed." >&2
            exit 1
            ;;
    esac

    case "$guard_mode" in
        managed)
            if [ -z "$current_branch" ]; then
                guard_refusal \
                    "$action from a managed lane with detached HEAD." \
                    "This lane must remain on its own branch '$expected_branch'."
            fi
            if [ "$current_branch" != "$expected_branch" ]; then
                guard_refusal \
                    "$action from managed lane branch '$current_branch'." \
                    "This lane belongs to '$expected_branch'; switch back before committing."
            fi
            ;;
        primary)
            if [ -z "$current_branch" ]; then
                return
            fi
            case "$current_branch" in
                maco/*)
                    guard_refusal \
                        "$action from the primary worktree on agent branch '$current_branch'." \
                        "Agent/lane branches must be committed from their managed worktrees."
                    ;;
            esac

            common_dir=$recorded_common_dir
            for expected_file in "$common_dir"/worktrees/*/maco-worktree-guard/expected-branch; do
                [ -r "$expected_file" ] || continue
                expected_branch=
                IFS= read -r expected_branch <"$expected_file" || :
                if [ -n "$expected_branch" ] && [ "$current_branch" = "$expected_branch" ]; then
                    guard_refusal \
                        "$action from the primary worktree on managed branch '$current_branch'." \
                        "That branch belongs to a managed lane worktree."
                fi
            done
            ;;
    esac
}

case "$hook_name" in
    pre-commit|pre-merge-commit)
        guard_branch_identity commit
        ;;
    pre-push)
        # The identity check deliberately does not read standard input. The
        # complete Git pre-push record stream remains available to the prior
        # dispatcher below, including the human-authorship guards.
        guard_branch_identity push
        ;;
esac

previous_hooks_state=previous-hooks-path
case "$hook_name" in
    pre-receive|update|proc-receive|post-receive|post-update|push-to-checkout)
        # Git runs receive-side hooks from $GIT_DIR. A relative core.hooksPath
        # therefore has a different effective location than hooks run from a
        # non-bare worktree root. proc-receive is conservatively kept with the
        # receive-side class even though it requires explicit protocol setup.
        previous_hooks_state=previous-git-dir-hooks-path
        ;;
    reference-transaction)
        # reference-transaction runs for both worktree-side ref changes and
        # receive-side transactions. Git enters $GIT_DIR for the latter, while
        # ordinary non-bare worktree operations run from the worktree. Select
        # the install-time relative-path base from that actual invocation
        # context instead of classifying this dual-context hook statically.
        reference_git_dir=$(git rev-parse --absolute-git-dir 2>/dev/null || :)
        reference_cwd=$(pwd -P 2>/dev/null || :)
        if [ -z "$reference_git_dir" ] || [ -z "$reference_cwd" ]; then
            guard_state_refusal \
                "$hook_name because its Git execution context cannot be resolved." \
                "Run 'maco worktree guard verify --repo <worktree>' and reinstall if needed."
        fi
        if [ "$reference_cwd" = "$reference_git_dir" ]; then
            previous_hooks_state=previous-git-dir-hooks-path
        fi
        ;;
esac

if [ ! -r "$guard_root/$previous_hooks_state" ]; then
    printf '%s\n' \
        "MACO worktree guard: prior hook path state is missing; refusing $hook_name." \
        "Run 'maco worktree guard verify --repo <worktree>' and reinstall if needed." >&2
    exit 1
fi
previous_hooks_path=
if ! IFS= read -r previous_hooks_path <"$guard_root/$previous_hooks_state"; then
    printf '%s\n' \
        "MACO worktree guard: prior hook path state is unreadable; refusing $hook_name." \
        "Run 'maco worktree guard verify --repo <worktree>' and reinstall if needed." >&2
    exit 1
fi
if [ -z "$previous_hooks_path" ]; then
    printf '%s\n' \
        "MACO worktree guard: prior hook path state is empty; refusing $hook_name." \
        "Run 'maco worktree guard verify --repo <worktree>' and reinstall if needed." >&2
    exit 1
fi

previous_hook=$previous_hooks_path/$hook_name
if [ -x "$previous_hook" ] && [ "$previous_hook" != "$hook_path" ]; then
    "$previous_hook" "$@"
    exit $?
fi

exit 0
