# Uses sed to actually set the directive, not `>>` append — the sshd_config collector uses
# first-occurrence-wins semantics (matching real sshd behavior), and Ubuntu's stock
# sshd_config already ships several directives uncommented (verified live: KbdInteractive
# Authentication, UsePAM, X11Forwarding, PrintMotd, AcceptEnv are all already present) — an
# appended duplicate line further down the file is silently ignored, not an override. This
# also matches the real technique: re-enabling password auth on an already-configured host
# is a sed-based edit of the existing directive, not an appended new one.
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/*
RUN grep -q '^PasswordAuthentication' /etc/ssh/sshd_config \
      && sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
      || echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config
RUN grep -q '^PermitRootLogin' /etc/ssh/sshd_config \
      && sed -i 's/^PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
      || echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
