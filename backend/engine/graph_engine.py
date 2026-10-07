"""
Graph Analytics Engine: Constructs and analyzes heterogeneous Entity-Event Provenance Graphs.
Connects users, devices, IP addresses, processes, files, and peripherals to reconstruct attack paths.
"""

from typing import List, Dict, Any, Tuple, Optional, Set
import networkx as nx
from backend.models import NormalizedEvent, GraphNode, GraphEdge, EventType


class ProvenanceGraphEngine:
    """Builds and analyzes multi-modal causal provenance graphs for security events."""

    def __init__(self):
        self.graph = nx.MultiDiGraph()
        self.node_metadata: Dict[str, Dict[str, Any]] = {}
        self.edge_records: List[Dict[str, Any]] = []

    def _ensure_node(self, node_id: str, label: str, node_type: str, attributes: Optional[Dict[str, Any]] = None):
        """Ensures a node exists with proper labeling and metadata."""
        if not self.graph.has_node(node_id):
            attrs = attributes or {}
            self.graph.add_node(
                node_id,
                label=label,
                node_type=node_type,
                is_compromised=False,
                risk_score=0.0,
                **attrs
            )
            self.node_metadata[node_id] = {
                "id": node_id,
                "label": label,
                "type": node_type,
                "is_compromised": False,
                "risk_score": 0.0,
                "attributes": attrs
            }

    def ingest_events(self, events: List[NormalizedEvent]):
        """Populates the provenance graph from an ordered list of normalized events."""
        for event in events:
            # 1. User & Host Nodes
            user_node = f"user:{event.actor_user}" if event.actor_user else None
            src_host_node = f"host:{event.source_host}" if event.source_host else None
            dst_host_node = f"host:{event.dest_host}" if event.dest_host else None
            src_ip_node = f"ip:{event.source_ip}" if event.source_ip else None
            dst_ip_node = f"ip:{event.dest_ip}" if event.dest_ip else None
            proc_node = f"proc:{event.process_name}" if event.process_name else None
            file_node = f"file:{event.file_path}" if event.file_path else None
            usb_node = f"usb:{event.device_id}" if event.device_id else None

            if user_node:
                self._ensure_node(user_node, event.actor_user, "User")
            if src_host_node:
                self._ensure_node(src_host_node, event.source_host, "Host")
            if dst_host_node:
                self._ensure_node(dst_host_node, event.dest_host, "Host")
            if src_ip_node:
                is_ext = not (event.source_ip.startswith("10.") or event.source_ip.startswith("192.168.") or event.source_ip.startswith("172.16.") or event.source_ip == "127.0.0.1")
                self._ensure_node(src_ip_node, event.source_ip, "IP", {"external": is_ext})
            if dst_ip_node:
                is_ext = not (event.dest_ip.startswith("10.") or event.dest_ip.startswith("192.168.") or event.dest_ip.startswith("172.16.") or event.dest_ip == "127.0.0.1")
                self._ensure_node(dst_ip_node, event.dest_ip, "IP", {"external": is_ext})
            if proc_node:
                self._ensure_node(proc_node, event.process_name, "Process", {"command": event.process_command or ""})
            if file_node:
                self._ensure_node(file_node, event.file_path.split("/")[-1].split("\\")[-1], "File", {"path": event.file_path})
            if usb_node:
                self._ensure_node(usb_node, event.device_id, "Device", {"type": "USB_STORAGE"})

            # Edges based on event semantics
            timestamp = event.timestamp
            evt_id = event.event_id

            raw_log = event.raw_log

            if event.event_type in (EventType.AUTH_LOGIN, EventType.AUTH_FAILED):
                if src_ip_node and dst_host_node:
                    self._add_edge(src_ip_node, dst_host_node, "CONNECTED_TO", timestamp, evt_id, raw_log)
                if user_node and dst_host_node:
                    self._add_edge(user_node, dst_host_node, "LOGGED_INTO", timestamp, evt_id, raw_log)
                elif user_node and src_host_node:
                    self._add_edge(user_node, src_host_node, "LOGGED_INTO", timestamp, evt_id, raw_log)
                if src_ip_node and user_node:
                    self._add_edge(src_ip_node, user_node, "USED_BY", timestamp, evt_id, raw_log)

            elif event.event_type == EventType.PROCESS_SPAWN:
                host = src_host_node or dst_host_node
                if user_node and proc_node:
                    self._add_edge(user_node, proc_node, "SPAWNED", timestamp, evt_id, raw_log)
                if host and proc_node:
                    self._add_edge(host, proc_node, "EXECUTED_ON", timestamp, evt_id, raw_log)
                if event.parent_process and proc_node:
                    parent_node = f"proc:{event.parent_process}"
                    self._ensure_node(parent_node, event.parent_process, "Process")
                    self._add_edge(parent_node, proc_node, "SPAWNED_CHILD", timestamp, evt_id, raw_log)

            elif event.event_type in (EventType.FILE_ACCESS, EventType.FILE_MODIFY):
                host = src_host_node or dst_host_node
                if user_node and file_node:
                    self._add_edge(user_node, file_node, "ACCESSED", timestamp, evt_id, raw_log)
                if proc_node and file_node:
                    self._add_edge(proc_node, file_node, "READ_WRITE", timestamp, evt_id, raw_log)
                if host and file_node:
                    self._add_edge(host, file_node, "STORED_ON", timestamp, evt_id, raw_log)

            elif event.event_type in (EventType.USB_MOUNT, EventType.USB_TRANSFER):
                host = src_host_node or dst_host_node
                if host and usb_node:
                    self._add_edge(host, usb_node, "MOUNTED_DEVICE", timestamp, evt_id, raw_log)
                if user_node and usb_node:
                    self._add_edge(user_node, usb_node, "OPERATED_DEVICE", timestamp, evt_id, raw_log)
                if file_node and usb_node:
                    self._add_edge(file_node, usb_node, "TRANSFERRED_TO", timestamp, evt_id, raw_log)

            elif event.event_type == EventType.NETWORK_CONNECT:
                if src_host_node and dst_ip_node:
                    self._add_edge(src_host_node, dst_ip_node, "OUTBOUND_TRAFFIC", timestamp, evt_id, raw_log)
                if src_ip_node and dst_host_node:
                    self._add_edge(src_ip_node, dst_host_node, "INBOUND_TRAFFIC", timestamp, evt_id, raw_log)
                if proc_node and dst_ip_node:
                    self._add_edge(proc_node, dst_ip_node, "OPENED_SOCKET", timestamp, evt_id, raw_log)

            elif event.event_type in (EventType.PRIVILEGE_ESCALATE, EventType.SERVICE_CREATE, EventType.LOG_CLEAR):
                host = src_host_node or dst_host_node
                if user_node and host:
                    self._add_edge(user_node, host, event.event_type.value, timestamp, evt_id, raw_log)

    def _add_edge(self, source: str, target: str, relation: str, timestamp: str, event_id: str, raw_log: Optional[str] = None):
        """Adds a directed edge and records metadata."""
        edge_id = f"edge-{len(self.edge_records) + 1}"
        self.graph.add_edge(
            source,
            target,
            key=edge_id,
            relation=relation,
            timestamp=timestamp,
            event_id=event_id,
            is_suspicious=False,
            stage_id=None,
            raw_log=raw_log
        )
        self.edge_records.append({
            "id": edge_id,
            "source": source,
            "target": target,
            "relation": relation,
            "timestamp": timestamp,
            "event_id": event_id,
            "is_suspicious": False,
            "tactic": None,
            "stage_id": None,
            "raw_log": raw_log
        })

    def mark_attack_subgraph(
        self,
        suspicious_event_ids: Set[str],
        compromised_entities: Set[str],
        stage_event_map: Optional[Dict[str, int]] = None
    ):
        """Marks nodes and edges involved in the attack chain with stage traceability."""
        stage_map = stage_event_map or {}
        for edge_rec in self.edge_records:
            if edge_rec["event_id"] in suspicious_event_ids:
                edge_rec["is_suspicious"] = True
                if edge_rec["event_id"] in stage_map:
                    edge_rec["stage_id"] = stage_map[edge_rec["event_id"]]
                if self.graph.has_edge(edge_rec["source"], edge_rec["target"]):
                    for _, edge_data in self.graph[edge_rec["source"]][edge_rec["target"]].items():
                        if edge_data.get("event_id") == edge_rec["event_id"]:
                            edge_data["is_suspicious"] = True
                            edge_data["stage_id"] = edge_rec.get("stage_id")

        for node_id in self.node_metadata:
            clean_name = self.node_metadata[node_id]["label"]
            raw_id = self.node_metadata[node_id]["id"]
            if clean_name in compromised_entities or raw_id in compromised_entities or any(c in raw_id for c in compromised_entities):
                self.node_metadata[node_id]["is_compromised"] = True
                self.node_metadata[node_id]["risk_score"] = 85.0
                if self.graph.has_node(node_id):
                    self.graph.nodes[node_id]["is_compromised"] = True

    def get_exportable_graph(self) -> Tuple[List[GraphNode], List[GraphEdge]]:
        """Exports the graph in Pydantic schema format for API and frontend display."""
        nodes = []
        for n_id, data in self.node_metadata.items():
            nodes.append(GraphNode(
                id=n_id,
                label=data["label"],
                type=data["type"],
                is_compromised=data.get("is_compromised", False),
                risk_score=data.get("risk_score", 0.0),
                attributes=data.get("attributes", {})
            ))

        edges = []
        for e in self.edge_records:
            edges.append(GraphEdge(
                id=e["id"],
                source=e["source"],
                target=e["target"],
                relation=e["relation"],
                timestamp=e["timestamp"],
                event_id=e["event_id"],
                is_suspicious=e.get("is_suspicious", False),
                tactic=e.get("tactic"),
                stage_id=e.get("stage_id"),
                raw_log=e.get("raw_log")
            ))
        return nodes, edges

    def find_causal_paths(self, start_entity: str, end_entity: str) -> List[List[str]]:
        """Finds directed simple paths between two entities in the provenance graph."""
        if not self.graph.has_node(start_entity) or not self.graph.has_node(end_entity):
            return []
        try:
            return list(nx.all_simple_paths(self.graph, source=start_entity, target=end_entity, cutoff=6))
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []
