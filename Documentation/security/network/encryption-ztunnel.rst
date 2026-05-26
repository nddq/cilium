.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _encryption_ztunnel:

*************************************
Ztunnel Transparent Encryption (Beta)
*************************************

.. include:: ../../beta.rst

This guide explains how to configure Cilium to use ztunnel for transparent
encryption and mutual TLS (mTLS) authentication between Cilium-managed endpoints.
ztunnel is a purpose-built per-node proxy that provides transparent Layer 4 mTLS
encryption and authentication for pod-to-pod communication.

When ztunnel is enabled in Cilium, the agent running on each cluster node
establishes a control plane connection with the local ztunnel proxy. Cilium
enrolls pods into the mesh on a per-namespace basis, allowing fine-grained
control over which workloads participate in mTLS encryption. Enrolled pods have
their traffic transparently redirected to the ztunnel proxy using iptables rules
configured in their network namespace, where the traffic is encrypted and
authenticated using mutual TLS before being sent to the destination.


Generating secrets for authentication
=====================================

Cilium's ztunnel integration requires a set of private keys and accompanying
to certificates be present via Kubernetes secrets. This follows the same pattern
as IPsec key injections.

These keys can be generated with the following bash script prior to deploying
Cilium.

.. literalinclude:: ../../../examples/kubernetes-ztunnel/generate-secrets.sh
   :language: bash

The 'bootstrap' keys are used to secure the connection between ztunnel and
Cilium's xDS and certificate server implementation.

The 'ca' keys are used as the root certificate for creating in-memory and
ephemeral client certificates on ztunnel's request.

Enable ztunnel in Cilium
========================

ztunnel can obtain workload certificates from one of two certificate authority
(CA) backends, selected with the ``encryption.ztunnel.ca.type`` Helm value:

``internal`` (default)
    Cilium's built-in CA signs ephemeral ztunnel certificates in memory using
    the ``ca`` keys generated above. This is convenient for testing and small
    deployments but is not backed by workload attestation.

``spire``
    An external `SPIRE <https://spiffe.io/>`__ server issues a short-lived
    X.509-SVID to each workload after attesting its Kubernetes identity. This is
    the recommended backend for production; see
    `Using SPIRE for workload identity`_.

The remainder of this section uses the default built-in CA.

Before you install Cilium with ztunnel enabled, ensure that:

* The necessary Kubernetes secrets are available.
* Cluster Mesh is not enabled (ztunnel is currently not compatible with Cluster Mesh).

.. tabs::

    .. group-tab:: Cilium CLI

       If you are deploying Cilium with the Cilium CLI, pass the following
       options:

       .. parsed-literal::

          cilium install |CHART_VERSION| \\
             --set encryption.enabled=true \\
             --set encryption.type=ztunnel

    .. group-tab:: Helm

       If you are deploying Cilium with Helm by following
       :ref:`k8s_install_helm`, pass the following options:

       .. parsed-literal::

           helm install cilium |CHART_RELEASE| \\
             --namespace kube-system \\
             --set encryption.enabled=true \\
             --set encryption.type=ztunnel


Using SPIRE for workload identity
=================================

For production deployments, configure ztunnel to use an external
`SPIRE <https://spiffe.io/>`__ server as its certificate authority instead of
Cilium's built-in CA. In this mode every workload receives a short-lived
X.509-SVID that SPIRE issues only after attesting the workload's Kubernetes
identity, and ztunnel presents that SVID on every mTLS handshake.

Cilium integrates with the SPIRE Helm charts published by the SPIFFE project
(`spiffe/helm-charts-hardened <https://github.com/spiffe/helm-charts-hardened>`__).
Cilium neither bundles nor manages SPIRE; you deploy and own the SPIRE
installation, which lets you take advantage of the full SPIRE feature set and
keep up with upstream SPIRE releases independently of Cilium.

How the integration works
-------------------------

* **cilium-operator**: connects to the SPIRE server's registration API and, for
  every enrolled namespace, registers a SPIFFE ID for each ServiceAccount
  (``spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>``) parented to
  the ztunnel identity. It removes those entries when a namespace is
  disenrolled.
* **ztunnel**: fetches those SVIDs on demand from the SPIRE agent's Delegated
  Identity API (over a Unix socket) and uses them for HBONE mTLS. Because
  attestation is process-based, ztunnel also mounts the node's container
  runtime socket to resolve workload PIDs.

Three bootstrap identities must therefore exist in SPIRE. They are few and
fixed, so this guide registers them as static entries with
``spire-server entry create`` rather than running the SPIRE controller manager
(see `Register the bootstrap identities`_):

.. list-table::
   :header-rows: 1

   * - Identity
     - SPIFFE ID
     - Purpose
   * - SPIRE agent node alias
     - ``spiffe://<trust-domain>/ns/<spire-namespace>/sa/spire-agent``
     - Stable parent for the workload entries below, matched to every SPIRE
       agent by its ``k8s_psat`` selectors.
   * - cilium-operator
     - ``spiffe://<trust-domain>/cilium-operator``
     - The operator's own identity (granted admin via ``spire-server.adminIDs``).
   * - ztunnel
     - ``spiffe://<trust-domain>/ztunnel``
     - ztunnel's own identity, and the delegate authorized on the SPIRE agent.

The per-namespace workload entries (``.../ns/<ns>/sa/<sa>``) are *not* static —
the cilium-operator creates and deletes them dynamically as namespaces are
enrolled. The cilium-operator is *not* a delegate: it authenticates to the SPIRE
server's registration API with its own SVID. Only ztunnel uses the Delegated
Identity API, and cilium-agent does not interact with SPIRE at all in this mode.

Prerequisites
-------------

* The ztunnel ``bootstrap`` secrets from `Generating secrets for authentication`_
  must still be present. SPIRE issues the workload certificates, but the
  channel between ztunnel and Cilium's xDS server is still secured with the
  ``bootstrap`` key pair. The ``ca`` keys are unused in this mode but the secret
  is still expected to contain all four keys.
* A trust domain that is identical across the SPIRE server, the SPIRE agent and
  Cilium. This guide uses ``cluster.local``, which is also ztunnel's default
  cluster domain.
* The container runtime socket path on your nodes. This guide assumes containerd
  at ``/run/containerd/containerd.sock``.
* A default ``StorageClass``. The upstream chart's SPIRE server keeps its
  datastore and CA keys on a 1Gi ``PersistentVolumeClaim`` provisioned from the
  cluster's default ``StorageClass`` (``spire-server.persistence.storageClass``
  defaults to ``null``); the ``spire-server`` pod stays ``Pending`` until one is
  available. For production, prefer an external database over the default
  on-disk SQLite — for example
  ``spire-server.dataStore.sql.databaseType: postgres`` — so registration state
  is durable and not tied to a single node's volume.

Deploy SPIRE
------------

Add the SPIFFE Helm repository and install the SPIRE CRDs:

.. code-block:: shell-session

    helm repo add spiffe https://spiffe.github.io/helm-charts-hardened/
    helm repo update spiffe
    helm upgrade --install spire-crds spiffe/spire-crds \
        --namespace spire-server --create-namespace

Create a ``spire-values.yaml`` file. It authorizes ztunnel as a delegate of the
SPIRE agent's Delegated Identity API, exposes the admin (delegated identity)
socket on the host via the SPIFFE CSI driver, and grants the cilium-operator
identity admin rights so it can manage entries:

.. code-block:: yaml

    global:
      k8s:
        clusterDomain: cluster.local
      spire:
        clusterName: <your-cluster-name>
        trustDomain: cluster.local

    spiffe-csi-driver:
      enabled: true

    spire-agent:
      # Authorize ztunnel to use the SPIRE agent Delegated Identity API.
      authorizedDelegates:
        - spiffe://cluster.local/ztunnel
      nodeAttestor:
        k8sPSAT:
          enabled: true
      workloadAttestors:
        k8s:
          verification:
            type: skip
      sockets:
        hostBasePath: /run/spire/sockets
        # Expose the admin/delegated-identity socket on the host so ztunnel
        # (running in the host network namespace) can reach it.
        admin:
          enabled: true
          mountOnHost: true

    spire-server:
      # Grant the cilium-operator identity rights to create/delete entries.
      adminIDs:
        - spiffe://cluster.local/cilium-operator
      # The bootstrap entries are registered statically (Step 2), so the
      # pod-watching controller manager is not needed.
      controllerManager:
        enabled: false
      dataStore:
        sql:
          databaseType: sqlite3

Install SPIRE:

.. code-block:: shell-session

    helm upgrade --install spire spiffe/spire \
        --namespace spire-server \
        -f spire-values.yaml

.. note::

   The chart's SPIRE agent helper init container pulls a ``bash`` image from
   ``cgr.dev`` (Chainguard) by default. If that registry is unreachable in your
   environment, override it with any image that ships ``bash`` — for example the
   Cilium agent image, which is already present on every node:

   .. code-block:: yaml

       spire-agent:
         socketAlternate:
           image:
             registry: quay.io
             repository: cilium/cilium
             tag: <cilium-version>   # any image that ships bash works
             pullPolicy: IfNotPresent

Register the bootstrap identities
---------------------------------

Register the three entries from the table above with the SPIRE server CLI, once
the server is ready. The agent node alias is a node entry (``-node``); the
operator and ztunnel entries are parented to it and selected by namespace +
ServiceAccount:

.. code-block:: shell-session

    SERVER="kubectl exec -n spire-server spire-server-0 -c spire-server -- \
        /opt/spire/bin/spire-server"
    SOCK="-socketPath /tmp/spire-server/private/api.sock"

    # Agent node alias (stable parent for the workload entries)
    $SERVER entry create $SOCK -node \
        -spiffeID spiffe://cluster.local/ns/spire-server/sa/spire-agent \
        -selector k8s_psat:agent_ns:spire-server \
        -selector k8s_psat:agent_sa:spire-agent

    # cilium-operator
    $SERVER entry create $SOCK \
        -spiffeID spiffe://cluster.local/cilium-operator \
        -parentID spiffe://cluster.local/ns/spire-server/sa/spire-agent \
        -selector k8s:ns:kube-system \
        -selector k8s:sa:cilium-operator

    # ztunnel (its ServiceAccount is "ztunnel-cilium")
    $SERVER entry create $SOCK \
        -spiffeID spiffe://cluster.local/ztunnel \
        -parentID spiffe://cluster.local/ns/spire-server/sa/spire-agent \
        -selector k8s:ns:kube-system \
        -selector k8s:sa:ztunnel-cilium

The operator's admin rights come from ``spire-server.adminIDs`` (Step 1), not
from a per-entry flag. These entries persist in the SPIRE datastore, so you only
create them once.

.. note::

   If you prefer a declarative, Kubernetes-native workflow — or expect to manage
   many identities — enable the SPIRE controller manager instead
   (``spire-server.controllerManager.enabled: true``) and create ``ClusterSPIFFEID``
   resources for ``cilium-operator`` (with ``admin: true``) and ``ztunnel``
   (matching pod label ``app: ztunnel-cilium``). The controller manager renders
   the entries automatically and parents them to the attested node, at the cost
   of running a controller that watches pods cluster-wide.

Install Cilium with the SPIRE backend
-------------------------------------

Create a ``cilium-spire-values.yaml`` file with the ztunnel SPIRE wiring:

.. code-block:: yaml

    encryption:
      enabled: true
      type: ztunnel
      ztunnel:
        ca:
          type: spire
        extraEnv:
          - name: SPIRE_ENABLED
            value: "true"
          - name: SPIRE_ADMIN_ENDPOINT_SOCKET
            value: unix:///run/spire/admin/admin.sock
        extraVolumes:
          - name: spire-admin-socket
            hostPath:
              path: /run/spire/sockets/csi.spiffe.io/admin
              type: DirectoryOrCreate
          - name: container-runtime-socket
            hostPath:
              path: /run/containerd/containerd.sock
              type: Socket
        extraVolumeMounts:
          - name: spire-admin-socket
            mountPath: /run/spire/admin
          - name: container-runtime-socket
            mountPath: /run/containerd/containerd.sock
            readOnly: true

    # ca.type=spire (above) starts the cilium-operator's SPIRE client and the
    # namespace enrollment reconciler. These operator flags point it at the
    # external SPIRE server and at the SPIRE agent's workload socket (used to
    # fetch the operator's own SVID); the volume mounts that socket from the host.
    operator:
      extraArgs:
        - --mesh-auth-spire-server-address=spire-server.spire-server.svc.cluster.local:443
        - --mesh-auth-spiffe-trust-domain=cluster.local
        - --mesh-auth-spire-agent-socket=/run/spire/agent-sockets/spire-agent.sock
      extraVolumes:
        - name: spire-agent-socket
          hostPath:
            path: /run/spire/agent-sockets
            type: DirectoryOrCreate
      extraVolumeMounts:
        - name: spire-agent-socket
          mountPath: /run/spire/agent-sockets
          readOnly: true

.. note::

   This wires the cilium-operator to SPIRE directly. Do **not** enable Cilium's
   :ref:`mutual authentication <gs_mutual_authentication>` feature
   (``authentication.mutual.spire``) for ztunnel: that is a separate feature
   that makes the cilium-agent a SPIRE delegate, which the ztunnel data path
   does not need.

Install (or upgrade) Cilium, keeping the ztunnel ``bootstrap`` secret from the
prerequisites in place:

.. parsed-literal::

    helm upgrade --install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        -f cilium-spire-values.yaml

Validate the SPIRE backend
--------------------------

#. Confirm the bootstrap entries exist:

   .. code-block:: shell-session

       kubectl exec -n spire-server spire-server-0 -c spire-server -- \
           /opt/spire/bin/spire-server entry show \
           -socketPath /tmp/spire-server/private/api.sock

   You should see the node-alias, ``spiffe://cluster.local/cilium-operator`` and
   ``spiffe://cluster.local/ztunnel`` entries.

#. Enroll a namespace (see `Enrolling Namespaces`_) and confirm the operator
   registered a workload entry for it, parented to the ztunnel identity:

   .. code-block:: shell-session

       kubectl exec -n spire-server spire-server-0 -c spire-server -- \
           /opt/spire/bin/spire-server entry show \
           -socketPath /tmp/spire-server/private/api.sock | grep -A3 "ns/<namespace>"

       SPIFFE ID        : spiffe://cluster.local/ns/<namespace>/sa/default
       Parent ID        : spiffe://cluster.local/ztunnel
       Selector         : k8s:ns:<namespace>
       Selector         : k8s:sa:default

#. Confirm ztunnel is encrypting traffic with SPIRE-issued identities. The
   ztunnel access log on the destination node shows the source and destination
   SPIFFE IDs and the HBONE port (15008):

   .. code-block:: shell-session

       kubectl -n kube-system logs ds/ztunnel-cilium | grep access

       ... src.identity="spiffe://cluster.local/ns/demo/sa/default" dst.addr=10.244.2.104:15008 \
           dst.hbone_addr=10.244.2.104:80 dst.identity="spiffe://cluster.local/ns/demo/sa/default" ...

Troubleshooting
---------------

``ztunnel`` logs ``ztunnelIdentity: null`` / ``No such file or directory``
    ztunnel cannot reach the SPIRE agent admin socket. Check that
    ``spire-agent.sockets.admin.mountOnHost`` is ``true``, that the host path in
    the ztunnel ``extraVolumes`` matches ``spire-agent.sockets.hostBasePath``
    (``.../csi.spiffe.io/admin``), and that the SPIRE agent is running on the
    node.

``ztunnel`` logs ``PermissionDenied: no identity issued``
    ztunnel's SPIFFE ID is not authorized for the Delegated Identity API, or its
    entry has not been created. Verify that ``spire-agent.authorizedDelegates``
    contains ``spiffe://<trust-domain>/ztunnel``, that the ztunnel entry exists in
    ``spire-server entry show``, and that its ``k8s:sa:`` selector matches the
    ztunnel ServiceAccount (``ztunnel-cilium``).

``cilium-agent`` logs ``spire-delegate`` / ``no identity issued`` errors
    Cilium's mutual authentication has been enabled (``authentication.mutual.spire``).
    It is a separate feature from ztunnel encryption and is not required here;
    leave it disabled so the agent does not act as a SPIRE delegate.

cilium-operator cannot register entries
    Ensure ``spire-server.adminIDs`` lists
    ``spiffe://<trust-domain>/cilium-operator``, that the operator entry exists,
    and that the operator's ``--mesh-auth-spire-server-address`` /
    ``--mesh-auth-spiffe-trust-domain`` match the SPIRE deployment.

Trust-domain mismatch
    The trust domain must be identical in ``global.spire.trustDomain``, the
    operator's ``--mesh-auth-spiffe-trust-domain`` flag and the SPIFFE IDs of the
    static entries. A mismatch causes SVID validation to fail closed.

Enrolling Namespaces
====================

After enabling ztunnel in Cilium, you need to explicitly enroll namespaces to
enable mTLS encryption for their workloads. This is done by applying a label
to the namespace:

.. code-block:: shell-session

    kubectl label namespace <namespace-name> io.cilium/mtls-enabled=true

To verify that a namespace is enrolled:

.. code-block:: shell-session

    kubectl get namespace <namespace-name> --show-labels

When a namespace is enrolled:

* All existing pods in the namespace (except ztunnel pods themselves) are enrolled
* Iptables rules are configured in each pod's network namespace for traffic redirection
* Pod metadata is sent to the ztunnel proxy via the ZDS protocol
* Future pods created in the namespace are automatically enrolled

To disenroll a namespace:

.. code-block:: shell-session

    kubectl label namespace <namespace-name> io.cilium/mtls-enabled-

This will:

#. Disenroll all pods in the namespace from ztunnel
#. Remove the iptables rules from each pod's network namespace
#. Notify ztunnel to stop processing traffic for those workloads

Validate the Setup
==================

#. Check that ztunnel has been enabled:

   .. code-block:: shell-session

      kubectl -n kube-system describe cm cilium-config | grep enable-ztunnel -A2

   You should see output indicating that ztunnel encryption is enabled.

#. Check which namespaces are enrolled:

   .. code-block:: shell-session

      kubectl get namespaces -l io.cilium/mtls-enabled=true

   This shows all namespaces labeled for ztunnel enrollment.

   To verify that these namespaces are actually enrolled in the StateDB table:

   .. code-block:: shell-session

      kubectl exec -n kube-system ds/cilium -- cilium-dbg statedb dump | jq '.["mtls-enrolled-namespaces"]'

   The results of this query should show which namespaces have been successfully
   processed by the enrollment reconciler.

#. Run a ``bash`` shell in one of the Cilium pods hosting a mtls-enrolled pod with
   ``kubectl -n kube-system exec -ti pod/<cilium-pod-hosting-mtls-pod> -- bash``
   and execute the following commands:

   Install tcpdump

   .. code-block:: shell-session

       $ apt-get update
       $ apt-get -y install tcpdump

   Check that traffic is encrypted. In the example below, this can be verified
   by the fact that packets will have a destination port of 15008 (HBONE).
   In the example below, ``eth0`` is the interface used for pod-to-pod
   communication. Replace this interface with e.g. ``cilium_vxlan`` if
   tunneling is enabled.

   .. code-block:: shell-session

       tcpdump -i eth0 port 15008
       tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
       listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
       13:00:06.982499 IP 10.244.1.95.15008 > 10.244.2.3.33446: ...
       13:00:06.982536 IP 10.244.2.3.33446 > 10.244.1.95.15008: ...
       13:00:06.982675 IP 10.244.2.3.33446 > 10.244.1.95.15008: ...


Limitations
===========

* Traffic between workloads is only supported when both the source and
  destination endpoints are enrolled in ztunnel. Communication between an
  enrolled workload and a non-enrolled workload is not supported.

* The ztunnel integration currently only supports enrollment via namespace
  labels. Pod-level enrollment is not supported.

* Only TCP traffic is currently supported for mTLS encryption. UDP and other
  protocols are not redirected to ztunnel.

* The integration requires iptables support in the kernel and cannot be used
  with environments that do not support iptables (such as some minimal container
  runtimes).

* Ztunnel interferes with Cilium network policy as traffic is encrypted before
  it leaves the pod, meaning L4 policies won't work except for directly
  targeting the ztunnel HBONE port (15008).

Known Issues
============

* Cluster Mesh is not currently supported when ztunnel is enabled. Attempting
  to enable both will result in a validation error.

* Pods without a network namespace path (such as host-networked pods) cannot
  be enrolled in ztunnel and will be skipped during enrollment.

