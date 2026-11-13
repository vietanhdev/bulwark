# The benign twin of ssh-includes-weak: a hardened server written with everything that could be
# misread as a weak value. `sshd -T` reports the safe value for every directive, so no SSH rule
# may fire:
#   - the word "yes" appears only inside trailing comments
#   - weak values sit in conditional Match blocks (one user, one group named "all"), which do not
#     apply to the host as a whole
#   - weak values sit in files the Include pattern does not match: a hidden file, a `.bak` copy,
#     and a file in a sub-folder
#   - PermitRootLogin and the forwarding directives use their restricted spellings
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/*
RUN set -e; \
    rm -rf /etc/ssh/sshd_config.d; mkdir -p /etc/ssh/sshd_config.d/old /run/sshd; \
    printf '%s\n' \
      'Include /etc/ssh/sshd_config.d/*.conf' \
      'PermitRootLogin "prohibit-password" # not yes' \
      'PermitEmptyPasswords no # never yes' \
      'X11Forwarding = no' \
      'allowtcpforwarding no' \
      'PermitUserEnvironment no' \
      'PermitTunnel no' \
      'StrictModes yes' \
      'GatewayPorts no' \
      'AllowAgentForwarding no' \
      'MaxAuthTries 3 # was 10' \
      'Match User deploy' \
      '    PasswordAuthentication yes' \
      '    X11Forwarding yes' \
      'Match Group all' \
      '    AllowTcpForwarding yes' \
      '    PermitRootLogin yes' \
      > /etc/ssh/sshd_config; \
    printf 'PasswordAuthentication no # was yes until the audit\n' \
      > /etc/ssh/sshd_config.d/10-site.conf; \
    printf 'PasswordAuthentication yes\nPermitEmptyPasswords yes\n' \
      > /etc/ssh/sshd_config.d/.disabled.conf; \
    printf 'PermitRootLogin yes\n' > /etc/ssh/sshd_config.d/10-site.conf.bak; \
    printf 'GatewayPorts yes\n' > /etc/ssh/sshd_config.d/old/90-old.conf; \
    sshd -t
