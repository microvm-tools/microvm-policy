# The workspace write-guard (modules/workspace.nix) in its opt-out shape:
# defaultOn, repoDepth and the AppArmor layer, confining the user manager
# (user@) that the workload runs under. Two guests, identical but for the
# state file: `guarded` has none (default on), `optout` says
# WORKSPACE_GUARD=0.
#
# At boot (before the guard) a repository exists two levels down, with a
# hook directory, an .envrc and a .mcp.json, and a second one whose name
# has a space ("my repo"), and a third named like a glob ("repo[ab]")
# beside a directory that glob would match ("repoa"); after boot the test
# clones another.
# Everything the test writes, it writes from the user manager
# (systemd-run --user), i.e. under the profile, the way the workload does.
#
# Asserted on `guarded`:
#   - the user manager runs under the profile (enforce);
#   - existing repository: a hook, its .git/config, .envrc, .githooks/ and
#     .claude/settings.json refused, the last three also by read-only binds;
#   - repository cloned after boot: clone and an ordinary commit work; a
#     hook (write, mkdir, rename onto, hard link, symlink), .envrc, .mcp.json,
#     .claude/commands/*, a directory renamed to .claude — refused;
#   - the documented limit holds as documented: the NEW repository's
#     .git/config is writable, and a directory renamed into place as a new
#     `.git` keeps its hooks/ (both asserted, so the documentation cannot
#     silently become false).
# On `optout`: the same writes succeed, under the open profile.
#
# `breakGuarded = true` seeds `guarded` with WORKSPACE_GUARD=0 too: the test
# must then FAIL.
{ pkgs, lib, breakGuarded ? false }:

let
  mkGuest = optOut: { ... }: {
    imports = [ ../modules/workspace.nix ];
    microvmPolicy = {
      stateFile = "/etc/microvm-policy/state.env";
      stateAfter = [ "instance-data.service" ];
      workspaceDir = "/ws";
      agentHome = "/home/agent";
      workspaceGuard = {
        defaultOn = true;
        repoDepth = 2;
        apparmor = {
          enable = true;
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
        ${lib.optionalString optOut "echo WORKSPACE_GUARD=0 > /etc/microvm-policy/state.env"}
        install -d -o agent -g users /ws /ws/team
        git init -q /ws/team/old
        git init -q "/ws/team/my repo"
        git init -q "/ws/team/repo[ab]"
        install -d /ws/team/repoa
        install -d /ws/team/old/.git/hooks
        echo '#!/bin/sh' > /ws/team/old/.git/hooks/pre-commit.sample
        echo 'use flake' > /ws/team/old/.envrc
        echo '{}' > /ws/team/old/.mcp.json
        install -d /ws/team/old/.githooks /ws/team/old/.claude
        echo '#!/bin/sh' > /ws/team/old/.githooks/pre-push
        echo '{}' > /ws/team/old/.claude/settings.json
        chown -R agent:users /ws
        git init -q -b main /srv/src
        git -C /srv/src -c user.name=t -c user.email=t@t commit -q --allow-empty -m init
        chown -R agent:users /srv/src
      '';
    };
  };
in
pkgs.testers.runNixOSTest {
  name = "workspace-guard${lib.optionalString breakGuarded "-broken"}";

  nodes.guarded = mkGuest breakGuarded;
  nodes.optout = mkGuest true;

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
    for m in (guarded, optout):
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
        # A glob-like name is that repository, not what the glob matches.
        guarded.succeed("findmnt -no OPTIONS '/ws/team/repo[ab]/.git/config' | grep -qw ro")

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

    with subtest("guarded: the documented limits are what the docs say"):
        ok(guarded, "git -C team/new config core.fsmonitor evil")
        ok(guarded, "mkdir -p /ws/g/hooks && echo evil > /ws/g/hooks/pre-commit && mkdir /ws/c && mv /ws/g /ws/c/.git && test -e /ws/c/.git/hooks/pre-commit")

    with subtest("optout: the same writes succeed, under the open profile"):
        assert "microvm-policy-workspace (enforce)" in ok(optout, "cat /proc/self/attr/current")
        ok(optout, "echo hook > team/old/.git/hooks/pre-commit")
        ok(optout, "echo x > team/old/.envrc")
        ok(optout, "git clone -q /srv/src team/new && mkdir team/new/.git/hooks && echo hook > team/new/.git/hooks/pre-commit")
        ok(optout, "echo x > team/new/.envrc && mkdir -p team/new/.claude/commands")
  '';
}
