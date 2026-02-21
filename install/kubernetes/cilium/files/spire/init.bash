# shellcheck disable=SC2086
set -e

echo "Waiting for spire-server process to start..."
while ! pgrep spire-server > /dev/null; do sleep 5; done

SPIRE_PID=$(pgrep spire-server)
SPIRE_SERVER_ROOT_PATH="/proc/${SPIRE_PID}/root"

spire_server() {
    chroot "${SPIRE_SERVER_ROOT_PATH}" /opt/spire/bin/spire-server "$@"
}

SOCKET_FLAG="-socketPath /tmp/spire-server/private/api.sock"

echo "Checking spire-server status"
while ! spire_server entry show ${SOCKET_FLAG} &> /dev/null; do
  echo "Waiting for spire-server to be ready..."
  sleep 5
done

echo "Spire Server is up, initializing cilium spire entries..."

AGENT_SPIFFE_ID="spiffe://{{ .Values.authentication.mutual.spire.trustDomain }}/ns/{{ .Values.authentication.mutual.spire.install.namespace }}/sa/spire-agent"
AGENT_SELECTORS="-selector k8s_psat:agent_ns:{{ .Values.authentication.mutual.spire.install.namespace }} -selector k8s_psat:agent_sa:spire-agent"
{{- if and .Values.encryption.enabled (eq .Values.encryption.type "ztunnel") }}
CILIUM_OPERATOR_SPIFFE_ID="spiffe://{{ .Values.authentication.mutual.spire.trustDomain }}/cilium-operator"
CILIUM_OPERATOR_SELECTORS="-selector k8s:ns:{{ include "cilium.namespace" . }} -selector k8s:sa:{{ .Values.serviceAccounts.operator.name }}"
ZTUNNEL_SPIFFE_ID="spiffe://{{ .Values.authentication.mutual.spire.trustDomain }}/ztunnel"
ZTUNNEL_SELECTORS="-selector k8s:ns:{{ include "cilium.namespace" . }} -selector k8s:sa:{{ .Values.serviceAccounts.ztunnel.name }}"
{{- else }}
CILIUM_AGENT_SPIFFE_ID="spiffe://{{ .Values.authentication.mutual.spire.trustDomain }}/cilium-agent"
CILIUM_AGENT_SELECTORS="-selector k8s:ns:{{ include "cilium.namespace" . }} -selector k8s:sa:{{ .Values.serviceAccounts.cilium.name }}"
CILIUM_OPERATOR_SPIFFE_ID="spiffe://{{ .Values.authentication.mutual.spire.trustDomain }}/cilium-operator"
CILIUM_OPERATOR_SELECTORS="-selector k8s:ns:{{ include "cilium.namespace" . }} -selector k8s:sa:{{ .Values.serviceAccounts.operator.name }}"
{{- end }}

while pgrep spire-server > /dev/null;
do
  echo "Ensuring agent entry"
  if spire_server entry show ${SOCKET_FLAG} -spiffeID $AGENT_SPIFFE_ID $AGENT_SELECTORS | grep -q "Found 0 entries" &> /dev/null; then
    spire_server entry create ${SOCKET_FLAG} -spiffeID $AGENT_SPIFFE_ID $AGENT_SELECTORS -node
  fi

  echo "Ensuring cilium-operator entry (required for creating SPIFFE identities)"
  if spire_server entry show ${SOCKET_FLAG} -spiffeID $CILIUM_OPERATOR_SPIFFE_ID $CILIUM_OPERATOR_SELECTORS | grep -q "Found 0 entries" &> /dev/null; then
    spire_server entry create ${SOCKET_FLAG} -spiffeID $CILIUM_OPERATOR_SPIFFE_ID -parentID $AGENT_SPIFFE_ID $CILIUM_OPERATOR_SELECTORS
  fi

{{- if and .Values.encryption.enabled (eq .Values.encryption.type "ztunnel") }}
  echo "Ensuring ztunnel entry (required for ztunnel to get its identity)"
  if spire_server entry show ${SOCKET_FLAG} -spiffeID $ZTUNNEL_SPIFFE_ID $ZTUNNEL_SELECTORS | grep -q "Found 0 entries" &> /dev/null; then
    spire_server entry create ${SOCKET_FLAG} -spiffeID $ZTUNNEL_SPIFFE_ID -parentID $AGENT_SPIFFE_ID $ZTUNNEL_SELECTORS
  fi
{{- else }}
  echo "Ensuring cilium-agent entry (required for the delegated identity to work)"
  if spire_server entry show ${SOCKET_FLAG} -spiffeID $CILIUM_AGENT_SPIFFE_ID $CILIUM_AGENT_SELECTORS | grep -q "Found 0 entries" &> /dev/null; then
    spire_server entry create ${SOCKET_FLAG} -spiffeID $CILIUM_AGENT_SPIFFE_ID -parentID $AGENT_SPIFFE_ID $CILIUM_AGENT_SELECTORS
  fi
{{- end }}

  echo "Cilium Spire entries are initialized successfully or already in-sync"
  sleep 30;
done
