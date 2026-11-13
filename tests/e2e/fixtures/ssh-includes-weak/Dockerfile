# The main file sets every directive to its safe value. Each weak value comes from somewhere the
# collector once missed, and each was checked against `sshd -T` on OpenSSH 9.6:
#   - a drop-in matched by a bracket pattern, with a trailing comment and a Latin-1 byte
#     (BLWK-SSH-001)
#   - a second pattern on the same Include line, with the value in quotes (BLWK-SSH-003)
#   - a quoted Include pattern, and values other than "yes" that still leave the feature on
#     (BLWK-SSH-005, BLWK-SSH-007, BLWK-SSH-009)
#   - a `Match all` block, which overrides the global value above it (BLWK-SSH-002)
# The file is written whole rather than edited with sed: nothing of the stock config is wanted.
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/*
RUN set -e; \
    rm -rf /etc/ssh/sshd_config.d; mkdir -p /etc/ssh/sshd_config.d /etc/ssh/quoted.d /run/sshd; \
    printf '%s\n' \
      'Include /etc/ssh/sshd_config.d/[0-9]?-*.conf /etc/ssh/extra.conf' \
      'Include "/etc/ssh/quoted.d/*.conf"' \
      'PasswordAuthentication no' \
      'PermitRootLogin no' \
      'PermitEmptyPasswords no' \
      'X11Forwarding no' \
      'AllowTcpForwarding no' \
      'PermitUserEnvironment no' \
      'PermitTunnel no' \
      'StrictModes yes' \
      'GatewayPorts no' \
      'AllowAgentForwarding no' \
      'MaxAuthTries 3' \
      'Match all' \
      'PermitRootLogin yes' \
      > /etc/ssh/sshd_config; \
    printf '# caf\351 (Latin-1)\nPasswordAuthentication yes # set by the image\n' \
      > /etc/ssh/sshd_config.d/50-cloud-init.conf; \
    printf 'PermitEmptyPasswords "yes"\n' > /etc/ssh/extra.conf; \
    printf '%s\n' 'AllowTcpForwarding all' 'PermitTunnel point-to-point' 'GatewayPorts clientspecified' \
      > /etc/ssh/quoted.d/forwarding.conf; \
    sshd -t
