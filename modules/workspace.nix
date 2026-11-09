# Guest-side guard for workspace paths whose contents execute on the HOST
# later, which is why the VM boundary does not cover them: .git/hooks and
# .git/config run on the next host-side git invocation (so do .githooks/ and
# .husky/ wherever core.hooksPath points there), .claude/{commands,agents},
# .claude/settings*.json hooks and .mcp.json are picked up by the next
# unsandboxed session that opens the directory, .vscode/ tasks by the editor,
# and .envrc runs under the host's direnv. A sandboxed session that can
# write these persists code past the VM teardown.
#
# Two layers, both off by default:
#
#   - read-only binds at boot (`paths`, at the workspace root and, with
#     `repoDepth`, in every repository found below it). They cover what exists
#     at boot, including a repository's .git/config, and pin existing .git
#     directories in place. They cannot cover what does not exist yet.
#   - an AppArmor profile (`apparmor.*`) for the units the guest workload
#     runs under: writes to the `denyPatterns` names are refused anywhere under
#     the workspace, at every syscall, so a repository cloned or created after
#     boot is covered the moment it exists — no watcher, no race. What it
#     cannot cover by construction: a NEW repository's .git/config and a
#     directory renamed into place as a new `.git` (git init and clone must be
#     able to create both, and a name rule cannot tell git from anything else
#     that writes the same path).
#
# Whether the guard is on is the state file's WORKSPACE_GUARD: opt-in ("1")
# by default, because straight denial breaks a workflow some consumers use —
# asking the agent to write a project skill or register an MCP server — or,
# with `defaultOn`, opt-out ("0") for guests less trusted than the machines
# the workspace reaches. Defence in depth, not a boundary.
#
# The same module carries WORKSPACE_MODE=ephemeral: the workspace
# becomes a guest-side overlay whose writes never reach the host — the
# complement of the guard. Passthrough stays the default: instant host-visible
# edits are the current contract and most of the point of virtiofs.
#
# Part of the microvm-policy layer — see modules/policy.nix for the options
# that decouple it from any one microVM's layout.
{ config, lib, pkgs, ... }:

let
  cfg = config.microvmPolicy;
  work = cfg.workspaceDir;
  # The systemd mount unit for a path, e.g. /work -> work.mount,
  # /home/agent -> home-agent.mount. Correct for the simple, space-free paths
  # a microVM share uses; used only for ordering.
  mountUnit = p: (lib.replaceStrings [ "/" ] [ "-" ] (lib.removePrefix "/" p)) + ".mount";

  gcfg = cfg.workspaceGuard;
  aa = gcfg.apparmor;

  # --- the AppArmor layer (workspaceGuard.apparmor) -------------------------
  # Two variants of ONE profile name, chosen at boot by the guard decision:
  # guarded (deny rules) or open (no deny rules). The confined units name the
  # profile WITHOUT systemd's "-" prefix, so if neither variant could be
  # loaded they refuse to start instead of running unconfined.
  #
  # Each pattern is a file or directory NAME that may sit anywhere under the
  # workspace; `w` covers create, write, truncate, mkdir and rename onto the
  # path, `l` hard links. Checked by the kernel at every syscall, so there is
  # no window between a repository appearing and it being guarded.
  aaRule = p: "  deny ${work}/{,**/}${p}{,/**} wl,";
  aaProfile = variant: pkgs.writeText "${aa.profileName}-${variant}" (''
    abi <abi/4.0>,
    include <tunables/global>
    profile ${aa.profileName} flags=(attach_disconnected, mediate_deleted) {
      all,
  '' + lib.optionalString (variant == "guarded") (lib.concatMapStringsSep "\n" aaRule aa.denyPatterns + "\n") + ''
    }
  '');
  aaLoad = variant: ''
    if ! ${pkgs.apparmor-parser}/bin/apparmor_parser -r ${aaProfile variant}; then
      echo "workspace-guard: could not load the AppArmor profile ${aa.profileName} (${variant}); the units it confines will not start" >&2
      exit 1
    fi
    echo "workspace-guard: AppArmor profile ${aa.profileName} loaded (${variant}) for: ${lib.concatStringsSep " " aa.units}"'';

  # The guard decision. Without defaultOn/AppArmor this is byte-for-byte the
  # original opt-in line.
  guardOn = if gcfg.defaultOn then ''[ "$guard" != "0" ]'' else ''[ "$guard" = "1" ]'';
  guardTest =
    if !gcfg.defaultOn && !aa.enable then
      ''[ "$guard" = "1" ] || exit 0''
    else
      ''
        if ! ${guardOn}; then
          ${lib.optionalString aa.enable (aaLoad "open")}
          echo "workspace-guard: off (WORKSPACE_GUARD=''${guard:-unset})"
          exit 0
        fi
        ${lib.optionalString aa.enable (aaLoad "guarded")}'';

  # workspaceGuard.repoDepth: the same read-only binds for every repository
  # below the workspace root, down to that depth, as found at boot. They pin
  # what AppArmor cannot: a repository's .git/config (git must be able to
  # create one in a new repository, so no name rule can forbid it), and they
  # make `mv .git elsewhere` fail (EBUSY) for a repository that exists.
  depthBlock = lib.optionalString (gcfg.repoDepth > 0) ''

    # NUL-separated and read whole: a repository named "my repo" or "*" is
    # one path, not words or a glob. Process substitution, not a pipe, so
    # $guarded survives the loop.
    while IFS= read -r -d "" git; do
      root=''${git%/.git}
      for rel in ${lib.escapeShellArgs gcfg.paths}; do
        p="$root/$rel"
        [ -e "$p" ] || continue
        mount --bind "$p" "$p"
        mount -o remount,bind,ro "$p"
        guarded="$guarded ''${root#${work}/}/$rel"
      done
    done < <(${pkgs.findutils}/bin/find ${work} -mindepth 2 -maxdepth ${toString (gcfg.repoDepth + 1)} \
        \( -name node_modules -o -name vendor -o -name .direnv \) -prune -o -name .git -prune -print0)'';

  # Shows what an ephemeral session changed: the overlay's upper layer holds
  # exactly the delta. Whiteouts (0:0 char devices) are deletions.
  vmWorkDiff = pkgs.writeShellScriptBin "vm-work-diff" ''
    # vm-work-diff [--patch] — list (or diff) this ephemeral session's changes
    # to the workspace. Copy anything worth keeping to ${cfg.agentHome} before
    # poweroff.
    up=/run/work-rw/upper
    lower=/run/work-lower
    if [ ! -d "$up" ]; then
      echo "vm-work-diff: not an ephemeral session (launch with WORKSPACE_MODE=ephemeral)" >&2
      exit 1
    fi
    patch=0
    [ "''${1:-}" = "--patch" ] && patch=1
    cd "$up"
    find . -mindepth 1 | sed 's|^\./||' | while IFS= read -r rel; do
      if [ -c "$up/$rel" ] && [ "$(stat -c %t:%T "$up/$rel")" = "0:0" ]; then
        echo "deleted:  $rel"
      elif [ -d "$up/$rel" ]; then
        continue
      elif [ -e "$lower/$rel" ]; then
        if [ "$patch" = 1 ]; then
          ${pkgs.diffutils}/bin/diff -u "$lower/$rel" "${work}/$rel" || true
        else
          echo "modified: $rel"
        fi
      else
        if [ "$patch" = 1 ]; then
          ${pkgs.diffutils}/bin/diff -u /dev/null "${work}/$rel" || true
        else
          echo "created:  $rel"
        fi
      fi
    done
  '';
in
{
  imports = [ ./policy.nix ];

  options.microvmPolicy.workspaceGuard = {
    paths = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [
        ".git/hooks"
        ".git/config"
        ".mcp.json"
        ".claude/commands"
        ".claude/agents"
        ".claude/settings.json"
        ".claude/settings.local.json"
        ".envrc"
        # core.hooksPath targets and hook managers: tracked, so they exist at
        # boot, and the host runs them on its next commit or push.
        ".githooks"
        ".husky"
        ".pre-commit-config.yaml"
        ".vscode"
      ];
      description = ''
        Paths under the workspace made read-only inside the guest when the
        session runs with WORKSPACE_GUARD=1. Relative to the workspace root;
        entries that do not exist at boot are skipped.
      '';
    };
    defaultOn = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Guard unless the state file says WORKSPACE_GUARD=0 (opt-out), instead
        of only when it says WORKSPACE_GUARD=1 (opt-in, the default). For
        guests that are less trusted than the machines the workspace syncs
        to.
      '';
    };
    repoDepth = lib.mkOption {
      type = lib.types.ints.unsigned;
      default = 0;
      description = ''
        Also apply `paths` to every git repository found at boot up to this
        many directories below the workspace root (node_modules, vendor and
        .direnv are skipped). 0: the workspace root only.
      '';
    };
    apparmor = {
      enable = lib.mkEnableOption ''
        the AppArmor layer of the guard: a profile that denies writes to
        `denyPatterns` anywhere under the workspace, for every process of the
        `units` it confines — including repositories cloned or created after
        boot, with no race (the kernel checks each syscall). Enables AppArmor
        and sets git's init.templateDir to an empty directory, so git init and
        clone create no .git/hooks to be refused. A NEW repository's
        .git/config, and a directory renamed into place as a new `.git`, are
        outside its reach (git must be able to create both)'';
      units = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [ "user@" "sshd" ];
        description = "systemd services (attribute names under systemd.services) whose processes run under the profile.";
      };
      profileName = lib.mkOption {
        type = lib.types.str;
        default = "microvm-policy-workspace";
        description = "Name of the AppArmor profile.";
      };
      denyPatterns = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [
          ".git/hooks"
          ".envrc"
          ".mcp.json"
          ".claude"
          ".vscode"
          ".githooks"
          ".husky"
          ".pre-commit-config.yaml"
        ];
        description = ''
          File or directory names (relative paths allowed, e.g. .git/hooks)
          that may not be created, written, renamed onto or hard-linked
          anywhere under the workspace while the guard is on; a directory
          entry covers everything below it.
        '';
      };
    };
  };

  config = lib.mkMerge [ {
    environment.systemPackages = [ vmWorkDiff ];

    systemd.services.work-ephemeral = {
      description = "Guest-side overlay over the workspace: writes never reach the host";
      after = [ (mountUnit work) ] ++ cfg.stateAfter;
      before = [ "workspace-guard.service" "getty@hvc0.service" ];
      wantedBy = [ "multi-user.target" ];
      # NixOS unit scripts default to coreutils/sed/grep on PATH — mount is
      # not among them. Found by the first real boot.
      path = [ pkgs.util-linux ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        mode=""
        if [ -f ${cfg.stateFile} ]; then
          mode=$(${pkgs.gnused}/bin/sed -n 's/^WORKSPACE_MODE=//p' ${cfg.stateFile} | tail -n1)
        fi
        [ "$mode" = "ephemeral" ] || exit 0

        # Keep the pristine host view reachable (for vm-work-diff and the
        # overlay's lowerdir) without disturbing systemd's workspace mount: a
        # bind, not a move. systemd makes / shared, so the overlay we mount
        # below would propagate into this bind and the "lower" would show the
        # upper's writes (vm-work-diff then calling every new file "modified").
        # --make-private detaches the bind from that peer group so it stays
        # pristine.
        mkdir -p /run/work-lower /run/work-rw
        mount --bind ${work} /run/work-lower
        mount --make-private /run/work-lower

        # The upper layer is RAM (its own tmpfs, so a runaway write fills
        # this mount, not /run): session writes cost memory and vanish at
        # poweroff — that is the feature. Overlay root attributes come from
        # the upper dir, so it must be the agent's.
        mount -t tmpfs -o mode=0755 tmpfs /run/work-rw
        install -d -o ${cfg.agentUser} -g ${cfg.agentUser} /run/work-rw/upper
        mkdir -p /run/work-rw/work
        mount -t overlay overlay \
          -o lowerdir=/run/work-lower,upperdir=/run/work-rw/upper,workdir=/run/work-rw/work \
          ${work}
        echo "work-ephemeral: ${work} is an overlay — writes stay in the VM (vm-work-diff lists them)"
      '';
    };

    systemd.services.workspace-guard = {
      description = "Read-only binds over workspace paths that execute on the host";
      after = [ (mountUnit work) ] ++ cfg.stateAfter ++ [ "work-ephemeral.service" ];
      before = [ "getty@hvc0.service" ];
      wantedBy = [ "multi-user.target" ];
      path = [ pkgs.util-linux ]; # mount — see work-ephemeral
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        guard=""
        if [ -f ${cfg.stateFile} ]; then
          guard=$(${pkgs.gnused}/bin/sed -n 's/^WORKSPACE_GUARD=//p' ${cfg.stateFile} | tail -n1)
        fi
        ${guardTest}

        guarded=""
        for rel in ${lib.escapeShellArgs cfg.workspaceGuard.paths}; do
          p="${work}/$rel"
          [ -e "$p" ] || continue
          # A bind of a path over itself plus a read-only remount of that
          # bind: the write fails with EROFS inside the guest while the host
          # view stays untouched. The agent user cannot undo it — the mounts
          # belong to the init namespace, which locks them against detach
          # from any user namespace the agent can create.
          mount --bind "$p" "$p"
          mount -o remount,bind,ro "$p"
          guarded="$guarded $rel"
        done${depthBlock}
        if [ -n "$guarded" ]; then
          echo "workspace-guard: read-only:$guarded"
        else
          echo "workspace-guard: enabled, but none of the guarded paths exist in ${work}"
        fi
      '';
    };
  }

  (lib.mkIf aa.enable {
    security.apparmor.enable = true;
    # With no template, git init/clone create no .git/hooks — which the
    # profile refuses — and nothing else changes for them.
    programs.git.enable = lib.mkDefault true;
    programs.git.config.init.templateDir = lib.mkDefault "${pkgs.runCommand "git-template-empty" { } "mkdir $out"}";

    systemd.services = lib.mkMerge [
      {
        # The confined units must not start before the profile is loaded,
        # and logins (user@) neither.
        workspace-guard.before = [ "systemd-user-sessions.service" ];
      }
      (lib.genAttrs aa.units (_: {
        wants = [ "workspace-guard.service" ];
        after = [ "workspace-guard.service" ];
        serviceConfig.AppArmorProfile = aa.profileName;
      }))
    ];
  })
  ];
}
