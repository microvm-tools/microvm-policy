# The workspace write-guard (modules/workspace.nix) in its opt-out shape:
# defaultOn, repoDepth and the AppArmor layer, confining the user manager
# (user@) that the workload runs under. Two guests, identical but for the
# state file: `guarded` has none (default on), `optout` says
# WORKSPACE_GUARD=0. A third, `optin`, has agent-vm's shape: opt-in
# (WORKSPACE_GUARD=1) and no AppArmor layer, so the boot-time binds alone.
#
# At boot (before the guard) a repository exists two levels down, with a
# hook directory, an .envrc and a .mcp.json, and a second one whose name
# has a space ("my repo"), and a third named like a glob ("repo[ab]")
# beside a directory that glob would match ("repoa"), with a submodule
# named "objects". The workspace root itself is a linked worktree of a
# repository deeper than repoDepth. The first has a
# submodule (its git dir under .git/modules) and a linked worktree with the
# submodule checked out (under .git/worktrees/<wt>/modules), per-worktree
# config on both; and a repository under the
# workspace root's vendor/ must stay unguarded. After boot the test clones
# another.
# Everything the test writes, it writes from the user manager
# (systemd-run --user), i.e. under the profile, the way the workload does.
#
# Asserted on `guarded`:
#   - the user manager runs under the profile (enforce);
#   - existing repository: a hook, its .git/config, .envrc, .githooks/ and
#     .claude/settings.json refused, the last three also by read-only binds;
#     a nested submodule's config and hooks, read-only by the binds alone;
#   - repository cloned after boot: clone and an ordinary commit work; a
#     hook (write, mkdir, rename onto, hard link, symlink), .envrc, .mcp.json,
#     .claude/commands/*, a directory renamed to .claude — refused; a
#     submodule added then, and checked out in a linked worktree: its hooks
#     (also nested, also renamed onto) refused;
#   - the documented limit holds as documented: the NEW repository's
#     .git/config is writable, and a directory renamed into place as a new
#     `.git` keeps its hooks/ (both asserted, so the documentation cannot
#     silently become false).
# On `optout`: the same writes succeed, under the open profile.
# On `optin`: the existing repository's paths, its submodule's, a nested
# submodule's and a linked worktree's submodule's are read-only binds
# (EBUSY/EROFS); a repository cloned after boot is not covered, as
# documented for this shape.
#
# `breakGuarded = true` seeds `guarded` with WORKSPACE_GUARD=0 and leaves
# `optin` without WORKSPACE_GUARD=1: the test must then FAIL.
{ pkgs, lib, breakGuarded ? false }:

let
  # state: the state file's WORKSPACE_GUARD ("" for none); optIn: agent-vm's
  # shape, opt-in and without the AppArmor layer.
  mkGuest = { state, optIn ? false }: { ... }: {
    imports = [ ../modules/workspace.nix ];
    microvmPolicy = {
      stateFile = "/etc/microvm-policy/state.env";
      stateAfter = [ "instance-data.service" ];
      workspaceDir = "/ws";
      agentHome = "/home/agent";
      workspaceGuard = {
        defaultOn = !optIn;
        repoDepth = 2;
        apparmor = {
          enable = !optIn;
          units = [ "user@" ];
        };
      };
    };
    users.users.agent = { isNormalUser = true; linger = true; };
    environment.systemPackages = [ pkgs.git ];
    programs.git.config.user = { name = "agent"; email = "agent@test"; };

    # The platform's instance data (cloud-init on KubeVirt) and a workspace
    # that already holds a repository two levels down.
    systemd.services.instance-data = {
      wantedBy = [ "multi-user.target" ];
      before = [ "workspace-guard.service" ];
      path = [ pkgs.git ];
      serviceConfig = { Type = "oneshot"; RemainAfterExit = true; };
      script = ''
        install -d -m 0755 /etc/microvm-policy
        : > /etc/microvm-policy/state.env
        ${lib.optionalString (state != "") "echo WORKSPACE_GUARD=${state} > /etc/microvm-policy/state.env"}
        git init -q -b main /srv/src
        git -C /srv/src -c user.name=t -c user.email=t@t commit -q --allow-empty -m init
        # The workspace root is a linked worktree; its repository lies
        # deeper than repoDepth, reached only through the root's .git file.
        git init -q -b main /srv/wsmain
        git -C /srv/wsmain -c user.name=t -c user.email=t@t commit -q --allow-empty -m init
        git -C /srv/wsmain config core.repositoryformatversion 1
        git -C /srv/wsmain config extensions.worktreeConfig true
        git -C /srv/wsmain worktree add -q /ws
        install -d /ws/deep/a/b
        mv /srv/wsmain /ws/deep/a/b/wsmain
        git -C /ws/deep/a/b/wsmain worktree repair /ws
        install -d /ws/deep/a/b/wsmain/.git/hooks
        git -C /ws config --worktree user.name root-wt
        install -d -o agent -g users /ws /ws/team
        git init -q /ws/team/old
        git init -q "/ws/team/my repo"
        git -C "/ws/team/my repo" -c protocol.file.allow=always submodule add -q /srv/src lib
        git init -q "/ws/team/repo[ab]"
        # A submodule NAMED objects: a git dir, not an object store.
        git -C "/ws/team/repo[ab]" -c protocol.file.allow=always submodule add -q /srv/src objects
        install -d /ws/team/repoa
        install -d /ws/team/old/.git/hooks
        echo '#!/bin/sh' > /ws/team/old/.git/hooks/pre-commit.sample
        echo 'use flake' > /ws/team/old/.envrc
        echo '{}' > /ws/team/old/.mcp.json
        install -d /ws/team/old/.githooks /ws/team/old/.claude
        echo '#!/bin/sh' > /ws/team/old/.githooks/pre-push
        echo '{}' > /ws/team/old/.claude/settings.json
        # A submodule: its checkout's .git is a file, its git dir is
        # team/old/.git/modules/sub.
        git -C /ws/team/old -c protocol.file.allow=always submodule add -q /srv/src sub
        install -d /ws/team/old/.git/modules/sub/hooks
        # A linked worktree of it (its .git a file too), with the submodule
        # checked out there: that git dir is under .git/worktrees/old-wt/
        # modules. And per-worktree config (extensions.worktreeConfig) on
        # both sides.
        git -C /ws/team/old -c user.name=t -c user.email=t@t commit -q -m init
        git -C /ws/team/old config core.repositoryformatversion 1
        git -C /ws/team/old config extensions.worktreeConfig true
        git -C /ws/team/old config --worktree user.name main-wt
        git -C /ws/team/old worktree add -q /ws/team/old-wt
        git -C /ws/team/old-wt -c protocol.file.allow=always submodule update -q --init
        install -d /ws/team/old/.git/worktrees/old-wt/modules/sub/hooks
        git -C /ws/team/old-wt config --worktree user.name linked-wt
        # A nested submodule (inside sub): its git dir is one modules/
        # further down, team/old/.git/modules/sub/modules/inner.
        git -C /ws/team/old/sub -c protocol.file.allow=always submodule add -q /srv/src inner
        install -d /ws/team/old/.git/modules/sub/modules/inner/hooks
        # A repository under vendor/ at the workspace root: skipped.
        git init -q /ws/vendor/dep
        chown -R agent:users /ws
        chown -R agent:users /srv/src
      '';
    };
  };
in
pkgs.testers.runNixOSTest {
  name = "workspace-guard${lib.optionalString breakGuarded "-broken"}";

  nodes.guarded = mkGuest { state = lib.optionalString breakGuarded "0"; };
  nodes.optout = mkGuest { state = "0"; };
  # Opt-in: without WORKSPACE_GUARD=1 it is off, which breakGuarded uses.
  nodes.optin = mkGuest { state = lib.optionalString (!breakGuarded) "1"; optIn = true; };

  testScript = ''
    def as_agent(m, cmd):
        # A transient unit in the agent's user manager: under the profile.
        return m.execute(
            "systemd-run --user --machine=agent@.host --wait --pipe -q "
            "-p Environment=PATH=/run/current-system/sw/bin -p WorkingDirectory=/ws "
            f"/run/current-system/sw/bin/bash -c '{cmd}' 2>&1"
        )

    def ok(m, cmd):
        rc, out = as_agent(m, cmd)
        assert rc == 0, f"{m.name}: expected success: {cmd}: rc={rc} {out}"
        return out

    def refused(m, cmd):
        rc, out = as_agent(m, cmd)
        assert rc != 0, f"{m.name}: expected refusal: {cmd}: {out}"
        assert any(r in out for r in ("denied", "Read-only", "Permission", "resource busy")), f"{m.name}: {cmd}: refused for another reason: {out}"
        print(f"{m.name} refused as expected: {cmd} :: {out.strip()}")

    start_all()
    for m in (guarded, optout, optin):
        m.wait_for_unit("workspace-guard.service")
        m.wait_for_unit("user@1000.service")
        print(m.succeed("journalctl -b -u workspace-guard -o cat --no-pager"))

    with subtest("the user manager runs under the profile"):
        assert "microvm-policy-workspace (enforce)" in ok(guarded, "cat /proc/self/attr/current")

    with subtest("guarded: existing repository"):
        refused(guarded, "echo evil > team/old/.git/hooks/pre-commit")
        refused(guarded, "git -C team/old config core.fsmonitor evil")
        refused(guarded, "echo evil > team/old/.envrc")
        refused(guarded, "echo evil > team/old/.mcp.json")
        refused(guarded, "echo evil > team/old/.githooks/pre-push")
        refused(guarded, "echo evil > team/old/.claude/settings.json")
        # Pinned by the boot-time binds too, not only by AppArmor: a consumer
        # without the AppArmor layer has only these.
        for p in (".git/config", ".githooks", ".claude/settings.json"):
            guarded.succeed(f"findmnt -no OPTIONS /ws/team/old/{p} | grep -qw ro")
        # A name with a space is one repository to the guard, not two words.
        guarded.succeed("findmnt -no OPTIONS '/ws/team/my repo/.git/config' | grep -qw ro")
        refused(guarded, "git -C \"team/my repo\" config core.fsmonitor evil")
        # Its only submodule has no config.worktree: the scan ends on a path
        # that does not exist, which must not fail the unit (set -e).
        guarded.succeed("findmnt -no OPTIONS '/ws/team/my repo/.git/modules/lib/config' | grep -qw ro")
        # A glob-like name is that repository, not what the glob matches.
        guarded.succeed("findmnt -no OPTIONS '/ws/team/repo[ab]/.git/config' | grep -qw ro")
        # Its submodule named objects is a git dir to guard, not a store to skip.
        guarded.succeed("findmnt -no OPTIONS '/ws/team/repo[ab]/.git/modules/objects/config' | grep -qw ro")
        # The workspace root is a linked worktree: through its .git file,
        # its config.worktree and its repository's config and hooks, which
        # lie beyond repoDepth.
        for p in ("deep/a/b/wsmain/.git/config", "deep/a/b/wsmain/.git/hooks",
                  "deep/a/b/wsmain/.git/worktrees/ws/config.worktree"):
            guarded.succeed(f"findmnt -no OPTIONS /ws/{p} | grep -qw ro")
        refused(guarded, "git -C /ws config core.fsmonitor evil")
        refused(guarded, "git -C /ws config --worktree core.fsmonitor evil")
        # A submodule's git dir is its superproject's .git/modules/<name>.
        for p in ("config", "hooks"):
            guarded.succeed(f"findmnt -no OPTIONS /ws/team/old/.git/modules/sub/{p} | grep -qw ro")
        refused(guarded, "git -C team/old/sub config core.fsmonitor evil")
        # A nested submodule present at boot, by the binds alone: findmnt
        # shows the bind, and EBUSY is the bind's refusal (AppArmor's would
        # be EACCES), so this holds for a consumer without the AppArmor layer.
        for p in ("config", "hooks"):
            guarded.succeed(f"findmnt -no OPTIONS /ws/team/old/.git/modules/sub/modules/inner/{p} | grep -qw ro")
        rc, out = as_agent(guarded, "git -C team/old/sub/inner config core.fsmonitor evil")
        assert rc != 0 and "resource busy" in out, f"nested submodule config not refused by the bind: {out}"
        rc, out = as_agent(guarded, "echo evil > team/old/.git/modules/sub/modules/inner/hooks/pre-commit")
        assert rc != 0 and "Read-only" in out, f"nested submodule hook not refused by the bind: {out}"
        # vendor/ is skipped at the workspace root too, as documented.
        guarded.fail("findmnt /ws/vendor/dep/.git/config")
        # A linked worktree's submodule, and per-worktree config on both
        # sides.
        for p in ("old/.git/config.worktree",
                  "old/.git/worktrees/old-wt/config.worktree",
                  "old/.git/worktrees/old-wt/modules/sub/config",
                  "old/.git/worktrees/old-wt/modules/sub/hooks"):
            guarded.succeed(f"findmnt -no OPTIONS /ws/team/{p} | grep -qw ro")
        refused(guarded, "git -C team/old-wt/sub config core.fsmonitor evil")
        refused(guarded, "git -C team/old-wt config --worktree core.fsmonitor evil")

    with subtest("guarded: repository cloned after boot"):
        ok(guarded, "git clone -q /srv/src team/new")
        ok(guarded, "echo hi > team/new/README && git -C team/new add README && git -C team/new commit -qm init")
        refused(guarded, "mkdir -p team/new/.git/hooks && echo evil > team/new/.git/hooks/pre-commit")
        refused(guarded, "mkdir team/new/.git/hooks")
        refused(guarded, "mkdir -p /ws/tmp1/hooks && mv /ws/tmp1/hooks team/new/.git/hooks")
        refused(guarded, "echo evil > /ws/f1 && ln /ws/f1 team/new/.envrc")
        refused(guarded, "ln -s /bin/sh team/new/.envrc")
        refused(guarded, "echo evil > /ws/f2 && mv /ws/f2 team/new/.envrc")
        refused(guarded, "echo evil > team/new/.envrc")
        refused(guarded, "echo {} > team/new/.mcp.json")
        refused(guarded, "mkdir -p team/new/.claude/commands")
        refused(guarded, "mkdir -p /ws/q/commands && echo x > /ws/q/commands/x.md && mv /ws/q team/new/.claude")
        # A submodule initialised after boot has no bind: its hooks (nested
        # ones too, and through a linked worktree) are the profile's alone.
        # Adding it, committing and checking it out in a worktree still work.
        ok(guarded, "git -C team/new -c protocol.file.allow=always submodule add -q /srv/src sub && git -C team/new commit -qm sub")
        refused(guarded, "mkdir team/new/.git/modules/sub/hooks")
        refused(guarded, "mkdir -p /ws/h1 && echo evil > /ws/h1/post-checkout && mv /ws/h1 team/new/.git/modules/sub/hooks")
        refused(guarded, "mkdir -p team/new/.git/modules/sub/modules/inner/hooks")
        ok(guarded, "git -C team/new worktree add -q /ws/team/new-wt && git -C team/new-wt -c protocol.file.allow=always submodule update -q --init")
        refused(guarded, "mkdir team/new/.git/worktrees/new-wt/modules/sub/hooks")

    with subtest("guarded: the documented limits are what the docs say"):
        ok(guarded, "git -C team/new config core.fsmonitor evil")
        ok(guarded, "mkdir -p /ws/g/hooks && echo evil > /ws/g/hooks/pre-commit && mkdir /ws/c && mv /ws/g /ws/c/.git && test -e /ws/c/.git/hooks/pre-commit")

    with subtest("optout: the same writes succeed, under the open profile"):
        assert "microvm-policy-workspace (enforce)" in ok(optout, "cat /proc/self/attr/current")
        ok(optout, "echo hook > team/old/.git/hooks/pre-commit")
        ok(optout, "echo x > team/old/.envrc")
        ok(optout, "git clone -q /srv/src team/new && mkdir team/new/.git/hooks && echo hook > team/new/.git/hooks/pre-commit")
        ok(optout, "echo x > team/new/.envrc && mkdir -p team/new/.claude/commands")

    with subtest("optin: agent-vm's shape, binds without AppArmor"):
        # Opt-in with WORKSPACE_GUARD=1 and no AppArmor layer: the boot-time
        # binds are all there is, nested submodules included.
        for p in ("old/.git/config", "old/.envrc", "old/.githooks",
                  "old/.git/modules/sub/config",
                  "old/.git/modules/sub/modules/inner/config",
                  "old/.git/modules/sub/modules/inner/hooks",
                  "old/.git/worktrees/old-wt/modules/sub/config"):
            optin.succeed(f"findmnt -no OPTIONS /ws/team/{p} | grep -qw ro")
        for cmd in ("git -C team/old config core.fsmonitor evil",
                    "git -C team/old/sub/inner config core.fsmonitor evil"):
            rc, out = as_agent(optin, cmd)
            assert rc != 0 and "resource busy" in out, f"optin: {cmd}: not refused by the bind: {out}"
        rc, out = as_agent(optin, "echo evil > team/old/.git/modules/sub/modules/inner/hooks/pre-commit")
        assert rc != 0 and "Read-only" in out, f"optin: nested submodule hook not refused: {out}"
        # The documented limit of this shape: what did not exist at boot is
        # not covered, a repository cloned after boot included.
        ok(optin, "git clone -q /srv/src team/new && mkdir -p team/new/.git/hooks && echo hook > team/new/.git/hooks/pre-commit")
  '';
}
