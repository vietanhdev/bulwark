# A generic reverse-tunnel-persistence systemd unit, in the same shape BLWK-PERSIST-001
# looks for: ExecStart referencing a tunneling tool, Restart=always so it survives both
# reboots and manual kills. Values here are entirely fictional/generic — no real hostnames,
# tokens, or domains — this fixture only needs to match the rule's condition pattern
# (exec_start matches "ngrok|cloudflared|serveo|localtunnel|ssh -R"), not reproduce anything
# real.
FROM ubuntu:24.04
# A shell heredoc (`cat <<'EOF'`) spanning multiple physical Dockerfile lines is NOT one RUN
# instruction unless every line ends in `\` — without that, each line is parsed as its own
# (invalid) Dockerfile instruction. `printf` with explicit `\n` keeps this a single RUN line,
# portable across both BuildKit and the legacy builder.
RUN mkdir -p /etc/systemd/system && printf '%s\n' \
    '[Unit]' \
    'Description=Sync Helper' \
    'After=network.target' \
    '' \
    '[Service]' \
    'ExecStart=/usr/local/bin/ngrok tcp 22' \
    'Restart=always' \
    'RestartSec=5' \
    '' \
    '[Install]' \
    'WantedBy=multi-user.target' \
    > /etc/systemd/system/sync-helper.service
