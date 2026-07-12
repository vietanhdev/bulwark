# Every directive all 11 ssh-remote-access rules read is explicitly set to its safe value —
# not just left at "absent" — so this genuinely exercises "the rule evaluates its condition
# and gets false", not "the field was missing so the condition errored instead of running".
# Handles both cases per directive (already present commented/uncommented -> replace in
# place; genuinely absent -> append) since Ubuntu's stock sshd_config already ships some of
# these uncommented (X11Forwarding, confirmed live) and not others — a blind append alone
# silently loses to first-occurrence-wins for the ones already present (see ssh-weak's
# Dockerfile comment for the collector semantics this works around).
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/*
RUN set -e; \
    set_directive() { \
      key="$1"; value="$2"; \
      if grep -qE "^#?${key}\b" /etc/ssh/sshd_config; then \
        sed -i -E "s|^#?${key}\b.*|${key} ${value}|" /etc/ssh/sshd_config; \
      else \
        echo "${key} ${value}" >> /etc/ssh/sshd_config; \
      fi; \
    }; \
    set_directive PasswordAuthentication no; \
    set_directive PermitRootLogin no; \
    set_directive PermitEmptyPasswords no; \
    set_directive X11Forwarding no; \
    set_directive AllowTcpForwarding no; \
    set_directive PermitUserEnvironment no; \
    set_directive PermitTunnel no; \
    set_directive StrictModes yes; \
    set_directive GatewayPorts no; \
    set_directive AllowAgentForwarding no; \
    set_directive MaxAuthTries 3
