#!/usr/bin/env bash
set -euo pipefail

readonly VERSION="0.1.0"
readonly STAGING="/root/kaleido-staging/bundle"
readonly WHEEL="/root/kaleido-staging/kaleido_protocol-0.1.0-py3-none-any.whl"
readonly WHEEL_SHA256="4f75ed3205259be847131f644419a0e45f1f10e9cf6b61f836ae1c0ca717c30f"
readonly RELEASE="/opt/kaleido/releases/${VERSION}"

if [[ ${EUID} -ne 0 ]]; then
  echo "installer must run as root" >&2
  exit 2
fi

for path in \
  "${WHEEL}" \
  "${STAGING}/kaleido.psk" \
  "${STAGING}/server-identity-private.pem" \
  "${STAGING}/server-tls-private.pem" \
  "${STAGING}/server-cert.pem" \
  "${STAGING}/server.json" \
  "${STAGING}/kaleido.service" \
  "${STAGING}/README.md"; do
  if [[ ! -f ${path} || -L ${path} ]]; then
    echo "missing or unsafe staging file: ${path}" >&2
    exit 2
  fi
done

echo "${WHEEL_SHA256}  ${WHEEL}" | sha256sum --check --status

if ss -H -ltn '( sport = :18443 )' | grep -q .; then
  echo "tcp/18443 is already occupied" >&2
  exit 2
fi

if ! getent passwd kaleido >/dev/null; then
  useradd --system --user-group --home-dir /var/lib/kaleido \
    --create-home --shell /usr/sbin/nologin kaleido
fi

install -d -o root -g root -m 0755 /opt/kaleido/releases
install -d -o root -g root -m 0755 "${RELEASE}"
install -d -o root -g kaleido -m 0750 /etc/kaleido/keys
install -d -o root -g kaleido -m 0750 /etc/kaleido/pki
install -d -o kaleido -g kaleido -m 0750 /var/lib/kaleido

if [[ ! -x ${RELEASE}/venv/bin/python ]]; then
  python3 -m venv "${RELEASE}/venv"
fi
"${RELEASE}/venv/bin/pip" install --disable-pip-version-check --no-cache-dir "${WHEEL}"
"${RELEASE}/venv/bin/python" -c \
  'import cryptography, kaleido; major=int(cryptography.__version__.split(".",1)[0]); assert major >= 45; print("runtime import OK")'

install -o root -g root -m 0644 "${STAGING}/README.md" "${RELEASE}/README.md"
install -o root -g kaleido -m 0640 "${STAGING}/kaleido.psk" /etc/kaleido/keys/kaleido.psk
install -o root -g kaleido -m 0640 \
  "${STAGING}/server-identity-private.pem" \
  /etc/kaleido/keys/server-identity-private.pem
install -o root -g kaleido -m 0640 \
  "${STAGING}/server-tls-private.pem" \
  /etc/kaleido/pki/server-tls-private.pem
install -o root -g root -m 0644 \
  "${STAGING}/server-cert.pem" \
  /etc/kaleido/pki/server-cert.pem
install -o root -g kaleido -m 0640 "${STAGING}/server.json" /etc/kaleido/server.json
install -o root -g root -m 0644 \
  "${STAGING}/kaleido.service" \
  /etc/systemd/system/kaleido.service

if [[ -e /opt/kaleido/current && ! -L /opt/kaleido/current ]]; then
  echo "/opt/kaleido/current exists and is not a symlink" >&2
  exit 2
fi
ln -sfn "${RELEASE}" /opt/kaleido/current

runuser -u kaleido -- \
  /opt/kaleido/current/venv/bin/kaleido validate --config /etc/kaleido/server.json
systemd-analyze verify /etc/systemd/system/kaleido.service

systemctl daemon-reload
ufw allow 18443/tcp comment 'Kaleido lab'
systemctl enable --now kaleido.service
systemctl is-active --quiet kaleido.service
ss -H -ltn '( sport = :18443 )' | grep -q .

echo "Kaleido laboratory carrier is active on tcp/18443"
