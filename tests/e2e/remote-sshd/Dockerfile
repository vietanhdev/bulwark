# A remote machine for the agentless remote-monitoring end-to-end test
# (crates/bulwarkctl/tests/e2e.rs::remote_monitoring_over_real_ssh).
#
# A real sshd, a `deploy` user that accepts one test key *and* a throw-away test password (so the
# "sign in once with a password, install a dedicated key" flow runs for real), and
# PasswordAuthentication left on so the scan has something genuine to report (BLWK-SSH rules). No Bulwark is installed, so the
# first scans exercise the copy-in / clean-up path. The test key is supplied at run time through
# a bind mount at /authorized_keys — never baked into the image.
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server sudo \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd \
    && useradd -m -s /bin/bash deploy \
    && echo 'deploy:bulwark-e2e-only' | chpasswd \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && printf 'AuthorizedKeysFile /authorized_keys/%%u .ssh/authorized_keys\nStrictModes no\n' \
         > /etc/ssh/sshd_config.d/10-test.conf
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
