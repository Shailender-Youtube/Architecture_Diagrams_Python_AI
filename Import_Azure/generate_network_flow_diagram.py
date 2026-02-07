#!/usr/bin/env python3
"""
Azure Network Flow Diagram Generator
Hub-Spoke topology with proper traffic flows.

Layout: TOP-DOWN
    Internet (top)
        ↓ HTTPS to external LBs
    Hub VNet (firewall VM for routing)
        ↓ VNet Peering (all traffic routes through hub)
    Spoke VNets (web/app tiers with LBs, VMSS, SQL, KV)
"""

import json
import os
import subprocess
import sys
from argparse import ArgumentParser
from pathlib import Path
from typing import Dict, List, Set, Tuple

from diagrams import Diagram, Cluster, Edge
from diagrams.azure.compute import VM, VMScaleSet
from diagrams.azure.network import (
    VirtualNetworks, Subnets, LoadBalancers,
    PublicIpAddresses, Firewall, VirtualNetworkGateways,
    PrivateEndpoint,
)
from diagrams.azure.database import SQLServers
from diagrams.azure.security import KeyVaults
from diagrams.azure.storage import StorageAccounts
from diagrams.onprem.network import Internet


# Professional muted colors (enterprise style)
HUB_COLOR = "#E8E8E8"          # Light gray
SPOKE_COLOR = "#F5F5F5"        # Very light gray
SUB_COLOR = "#FAFAFA"          # Near white
RG_COLOR = "#FFFFFF"           # White
WEB_COLOR = "#F0F0F0"          # Light gray
APP_COLOR = "#F0F0F0"          # Light gray
DATA_COLOR = "#F0F0F0"         # Light gray
PE_COLOR = "#F0F0F0"           # Light gray
FW_COLOR = "#E0E0E0"           # Slightly darker gray
INTERNET_COLOR = "#E8E8E8"     # Light gray


class AzureNetworkDiagramGenerator:
    def __init__(self, input_file: str, output_name: str = "network_flow_diagram"):
        self.input_file = input_file
        self.output_name = output_name
        self.output_dir = Path("diagrams")
        self.output_dir.mkdir(exist_ok=True)

        self.infrastructure: Dict = {}
        self.vnet_map: Dict[str, Dict] = {}
        self.subnet_map: Dict[str, Dict] = {}
        self.nic_subnet_map: Dict[str, str] = {}
        self.resource_subnet_map: Dict[str, str] = {}

        self.hub_vnets: Set[str] = set()
        self.spoke_vnets: Set[str] = set()
        self.peerings: List[Dict] = []
        self.private_endpoints: List[Dict] = []

        self.nodes: Dict[str, object] = {}
        self.vnet_nodes: Dict[str, object] = {}
        self.drawn_peerings: Set[Tuple[str, str]] = set()

        # Track for traffic flows
        self.external_lbs: List = []
        self.hub_fw_nodes: List = []
        self.spoke_lbs: List = []

    def load_infrastructure(self):
        print(f"📂 Loading {self.input_file}...")
        with open(self.input_file, "r") as f:
            self.infrastructure = json.load(f)
        subs = self.infrastructure.get("subscriptions", [])
        print(f"   {len(subs)} subscription(s)")

    def analyze_topology(self):
        print("🔍 Analyzing topology...")
        all_vnet_ids = []

        for sub in self.infrastructure.get("subscriptions", []):
            sub_id = sub.get("subscriptionId", "")
            sub_name = sub.get("displayName", "")
            for rg in sub.get("resourceGroups", []):
                rg_name = rg.get("resourceGroupName", "")
                net = rg.get("resources", {}).get("network", {})
                compute = rg.get("resources", {}).get("compute", {})

                # NICs → subnet
                for nic in net.get("networkInterfaces", []):
                    nic_id = nic.get("id", "")
                    ip_cfgs = nic.get("ip_configurations", [])
                    if ip_cfgs:
                        sid = ip_cfgs[0].get("subnet", {}).get("id", "")
                        if sid:
                            self.nic_subnet_map[nic_id] = sid

                # Private Endpoints
                for pe in net.get("privateEndpoints", []):
                    self.private_endpoints.append({
                        "id": pe.get("id", ""),
                        "name": pe.get("name", ""),
                        "subnet_id": pe.get("subnet", {}).get("id", ""),
                        "connections": pe.get("private_link_service_connections", []),
                    })

                # VNets
                for vnet in net.get("virtualNetworks", []):
                    vid = vnet.get("id", "")
                    vname = vnet.get("name", "")
                    all_vnet_ids.append(vid)

                    self.vnet_map[vid] = {
                        **vnet,
                        "rg_name": rg_name,
                        "sub_name": sub_name,
                        "sub_id": sub_id,
                        "compute": compute,
                        "network": net,
                        "sql": rg.get("resources", {}).get("sql", {}),
                        "keyvault": rg.get("resources", {}).get("keyvault", {}),
                    }

                    # Hub detection
                    if "hub" in vname.lower():
                        self.hub_vnets.add(vid)

                    for sn in vnet.get("subnets", []):
                        sn_id = sn.get("id", "")
                        self.subnet_map[sn_id] = {**sn, "vnet_id": vid, "vnet_name": vname}
                        if "firewall" in sn.get("name", "").lower():
                            self.hub_vnets.add(vid)

                    # Peerings
                    for peer in vnet.get("virtual_network_peerings", []):
                        remote_id = peer.get("remote_virtual_network", {}).get("id", "")
                        self.peerings.append({
                            "source": vid,
                            "target": remote_id,
                            "state": peer.get("peering_state", "Unknown"),
                        })

                # Map resources → subnets
                self._map_resources(rg)

        # Spokes = not hub
        for vid in all_vnet_ids:
            if vid not in self.hub_vnets:
                self.spoke_vnets.add(vid)

        print(f"   Hub: {len(self.hub_vnets)}, Spokes: {len(self.spoke_vnets)}, Peerings: {len(self.peerings)}")

    def _map_resources(self, rg: Dict):
        compute = rg.get("resources", {}).get("compute", {})
        network = rg.get("resources", {}).get("network", {})

        for vm in compute.get("virtualMachines", []):
            vm_id = vm.get("id", "")
            nics = vm.get("network_profile", {}).get("network_interfaces", [])
            if nics:
                nic_id = nics[0].get("id", "")
                if nic_id in self.nic_subnet_map:
                    self.resource_subnet_map[vm_id] = self.nic_subnet_map[nic_id]

        for vmss in compute.get("virtualMachineScaleSets", []):
            vmss_id = vmss.get("id", "")
            nic_cfgs = (vmss.get("virtual_machine_profile", {})
                            .get("network_profile", {})
                            .get("network_interface_configurations", []))
            if nic_cfgs:
                ip_cfgs = nic_cfgs[0].get("ip_configurations", [])
                if ip_cfgs:
                    sid = ip_cfgs[0].get("subnet", {}).get("id", "")
                    if sid:
                        self.resource_subnet_map[vmss_id] = sid

        for lb in network.get("loadBalancers", []):
            lb_id = lb.get("id", "")
            fe_cfgs = lb.get("frontend_ip_configurations", [])
            if fe_cfgs:
                # Check if external (has public IP) or internal (has subnet)
                pip = fe_cfgs[0].get("public_ip_address", {})
                sid = fe_cfgs[0].get("subnet", {}).get("id", "")
                if sid:
                    self.resource_subnet_map[lb_id] = sid

    def generate_diagram(self):
        print("🎨 Generating diagram...")
        
        # Check for GraphViz
        if not self._check_graphviz():
            print("\n❌ Error: GraphViz is not installed or not on PATH")
            print("\n📥 Install GraphViz:")
            print("   Option 1 - Using Chocolatey:")
            print("      choco install graphviz")
            print("   Option 2 - Download installer:")
            print("      https://graphviz.org/download/")
            print("\n   After installation, restart your terminal or add GraphViz bin folder to PATH")
            sys.exit(1)
        
        output_path = str(self.output_dir / self.output_name)

        graph_attr = {
            "splines": "ortho",
            "nodesep": "0.8",
            "ranksep": "1.2",
            "fontsize": "14",
            "fontname": "Segoe UI",
            "bgcolor": "white",
            "pad": "0.8",
            "compound": "true",
            "rankdir": "TB",
        }

        with Diagram(
            name="Azure Network Flow Diagram",
            filename=output_path,
            show=False,
            direction="TB",
            graph_attr=graph_attr,
            node_attr={"fontsize": "10", "fontname": "Segoe UI"},
            edge_attr={"fontsize": "9", "fontname": "Segoe UI"},
            outformat=["png", "dot"],
        ):
            # ══════════════════════════════════════════════════════════
            # INTERNET (TOP)
            # ══════════════════════════════════════════════════════════
            with Cluster("External", graph_attr={"bgcolor": INTERNET_COLOR, "style": "rounded", "margin": "15"}):
                internet = Internet("Internet\nUsers")

            # ══════════════════════════════════════════════════════════
            # SUBSCRIPTIONS with Hub at top, Spokes below
            # ══════════════════════════════════════════════════════════
            # Group VNets by subscription
            subs_data = {}
            for vid, vdata in self.vnet_map.items():
                sub_name = vdata.get("sub_name", "Unknown")
                if sub_name not in subs_data:
                    subs_data[sub_name] = {"hub": [], "spoke": []}
                if vid in self.hub_vnets:
                    subs_data[sub_name]["hub"].append(vdata)
                else:
                    subs_data[sub_name]["spoke"].append(vdata)

            # Render subscriptions
            for sub_name, vnets in subs_data.items():
                with Cluster(f"☁️ {sub_name}", graph_attr={
                    "bgcolor": SUB_COLOR, "style": "rounded", "margin": "20", "fontsize": "14"
                }):
                    # Hub VNets first
                    for vdata in vnets["hub"]:
                        self._render_vnet(vdata, is_hub=True)

                    # Spoke VNets
                    for vdata in vnets["spoke"]:
                        self._render_vnet(vdata, is_hub=False)

            # ══════════════════════════════════════════════════════════
            # TRAFFIC FLOWS
            # ══════════════════════════════════════════════════════════
            
            # Internet → External LBs (HTTPS)
            for lb in self.external_lbs[:4]:
                internet >> Edge(label="HTTPS", color="green", style="bold", penwidth="2") >> lb

            # Hub FW → Internal traffic routing (all spoke traffic goes through hub)
            if self.hub_fw_nodes and self.spoke_lbs:
                for lb in self.spoke_lbs[:4]:
                    self.hub_fw_nodes[0] >> Edge(
                        label="Routed\nTraffic", color="blue", style="dashed", penwidth="1.5"
                    ) >> lb

            # VNet Peerings
            self._draw_peerings()

            # Private Endpoint → SQL/KV
            for pe in self.private_endpoints:
                pe_id = pe["id"]
                if pe_id in self.nodes:
                    pe_node = self.nodes[pe_id]
                    for conn in pe.get("connections", []):
                        target_id = conn.get("private_link_service_id", "")
                        if target_id in self.nodes:
                            pe_node >> Edge(label="Private\nLink", color="orange", style="bold") >> self.nodes[target_id]

        print(f"   ✅ {output_path}.png")
        print(f"   ✅ {output_path}.dot")
        self._convert_to_drawio(output_path)

    def _render_vnet(self, vdata: Dict, is_hub: bool):
        vid = vdata.get("id", "")
        vname = vdata.get("name", "VNet")
        cidrs = vdata.get("address_space", {}).get("address_prefixes", [])
        cidr_str = ", ".join(cidrs)
        rg_name = vdata.get("rg_name", "")

        color = HUB_COLOR if is_hub else SPOKE_COLOR
        icon = "🏢 HUB" if is_hub else "🌐 SPOKE"

        compute = vdata.get("compute", {})
        network = vdata.get("network", {})
        sql_res = vdata.get("sql", {})
        kv_res = vdata.get("keyvault", {})

        all_nodes = []

        with Cluster(f"📂 {rg_name}", graph_attr={"bgcolor": RG_COLOR, "style": "rounded", "margin": "15", "fontsize": "11"}):
            with Cluster(f"{icon}: {vname}\n{cidr_str}", graph_attr={
                "bgcolor": color, "style": "rounded", "margin": "15", "fontsize": "11"
            }):
                for sn in vdata.get("subnets", []):
                    nodes = self._render_subnet(sn, network, compute, is_hub)
                    all_nodes.extend(nodes)

                # SQL Servers (inside VNet cluster, in data subnet area)
                for srv in sql_res.get("servers", []):
                    srv_id = srv.get("id", "")
                    if srv_id not in self.nodes:
                        dbs = [d["name"] for d in sql_res.get("databases", []) if d.get("name") != "master"]
                        label = f"{srv['name']}\n({', '.join(dbs)})" if dbs else srv['name']
                        node = SQLServers(label)
                        self.nodes[srv_id] = node
                        all_nodes.append(node)

                # Key Vaults (inside VNet cluster)
                for kv in kv_res.get("vaults", []):
                    kv_id = kv.get("id", "")
                    if kv_id not in self.nodes:
                        node = KeyVaults(kv["name"])
                        self.nodes[kv_id] = node
                        all_nodes.append(node)

        # Representative node for peering
        rep = all_nodes[0] if all_nodes else VirtualNetworks(vname)
        self.vnet_nodes[vid] = rep

    def _render_subnet(self, sn: Dict, network: Dict, compute: Dict, is_hub: bool) -> List:
        sn_id = sn.get("id", "")
        sn_name = sn.get("name", "Subnet")
        sn_cidr = sn.get("address_prefix", "")
        low = sn_name.lower()

        # Color by purpose
        if "firewall" in low or "fw" in low:
            color = FW_COLOR
        elif "web" in low or "ingress" in low:
            color = WEB_COLOR
        elif "app" in low:
            color = APP_COLOR
        elif "data" in low:
            color = DATA_COLOR
        elif "pe" in low or "endpoint" in low:
            color = PE_COLOR
        else:
            color = "#FFFFFF"

        nodes = []

        with Cluster(f"{sn_name}\n{sn_cidr}", graph_attr={"bgcolor": color, "margin": "10", "fontsize": "9"}):
            # VMs (firewall VM in hub)
            for vm in compute.get("virtualMachines", []):
                vm_id = vm.get("id", "")
                if self.resource_subnet_map.get(vm_id) == sn_id:
                    name = vm.get("name", "VM")
                    size = vm.get("hardware_profile", {}).get("vm_size", "")
                    # Check if this is a firewall VM
                    if "fw" in name.lower() or "firewall" in name.lower():
                        n = VM(f"🔥 {name}\n(NVA)")
                        self.hub_fw_nodes.append(n)
                    else:
                        n = VM(f"{name}\n{size}")
                    nodes.append(n)
                    self.nodes[vm_id] = n

            # VMSS
            for vmss in compute.get("virtualMachineScaleSets", []):
                vmss_id = vmss.get("id", "")
                if self.resource_subnet_map.get(vmss_id) == sn_id:
                    name = vmss.get("name", "VMSS")
                    cap = vmss.get("sku", {}).get("capacity", "?")
                    n = VMScaleSet(f"{name}\nx{cap}")
                    nodes.append(n)
                    self.nodes[vmss_id] = n

            # Load Balancers
            for lb in network.get("loadBalancers", []):
                lb_id = lb.get("id", "")
                lb_name = lb.get("name", "LB")
                fe_cfgs = lb.get("frontend_ip_configurations", [])
                
                # Check if external (public IP) or internal (subnet)
                is_external = False
                if fe_cfgs:
                    pip = fe_cfgs[0].get("public_ip_address", {})
                    if pip and pip.get("id"):
                        is_external = True
                    sid = fe_cfgs[0].get("subnet", {}).get("id", "")
                    if sid == sn_id or is_external:
                        sku = lb.get("sku", {}).get("name", "")
                        if is_external:
                            lb_node = LoadBalancers(f"🌐 {lb_name}\n(External)")
                            self.external_lbs.append(lb_node)
                        else:
                            lb_node = LoadBalancers(f"{lb_name}\n(Internal)")
                            self.spoke_lbs.append(lb_node)
                        nodes.append(lb_node)
                        self.nodes[lb_id] = lb_node

                        # LB → VMSS backend
                        for pool in lb.get("backend_address_pools", []):
                            for bip in pool.get("backend_ip_configurations", []):
                                bip_id = bip.get("id", "")
                                for vmss in compute.get("virtualMachineScaleSets", []):
                                    if vmss["id"] in bip_id and vmss["id"] in self.nodes:
                                        lb_node >> Edge(label="Backend", color="blue") >> self.nodes[vmss["id"]]

            # Private Endpoints
            for pe in self.private_endpoints:
                if pe["subnet_id"] == sn_id:
                    n = PrivateEndpoint(pe["name"])
                    nodes.append(n)
                    self.nodes[pe["id"]] = n

            # Empty placeholder
            if not nodes:
                placeholder = Subnets(sn_name)
                nodes.append(placeholder)

        return nodes

    def _draw_peerings(self):
        for p in self.peerings:
            src, tgt = p["source"], p["target"]
            key = tuple(sorted([src, tgt]))
            if key in self.drawn_peerings:
                continue
            if src in self.vnet_nodes and tgt in self.vnet_nodes:
                self.drawn_peerings.add(key)
                state = p["state"]
                is_hub = src in self.hub_vnets or tgt in self.hub_vnets
                style = "bold" if is_hub else "dashed"
                self.vnet_nodes[src] >> Edge(
                    label=f"VNet Peering\n{state}", color="blue", style=style, dir="both", penwidth="2"
                ) >> self.vnet_nodes[tgt]

    def _convert_to_drawio(self, base: str):
        dot_f = f"{base}.dot"
        drawio_f = f"{base}.drawio"
        try:
            subprocess.run(["graphviz2drawio", dot_f, "-o", drawio_f], check=True, capture_output=True)
            print(f"   ✅ {drawio_f}")
        except:
            print("   ⚠️  graphviz2drawio failed")

    def _check_graphviz(self) -> bool:
        """Check if GraphViz is installed and accessible."""
        import shutil
        
        # First try: Check if 'dot' is on PATH
        if shutil.which('dot'):
            return True
        
        # Second try: Check common Windows installation paths
        common_paths = [
            r"C:\Program Files\Graphviz\bin\dot.exe",
            r"C:\Program Files (x86)\Graphviz\bin\dot.exe",
            r"C:\ProgramData\chocolatey\bin\dot.exe",
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                # Add to PATH for this session
                graphviz_bin = os.path.dirname(path)
                os.environ['PATH'] = f"{graphviz_bin}{os.pathsep}{os.environ['PATH']}"
                print(f"   ✅ Found GraphViz at: {graphviz_bin}")
                return True
        
        return False

    def run(self):
        print("\n" + "=" * 60)
        print("🌐 Azure Network Flow Diagram Generator")
        print("=" * 60)
        self.load_infrastructure()
        self.analyze_topology()
        self.generate_diagram()
        print("\n✅ Done!")
        print(f"   Resources: {len(self.nodes)}")


def main():
    parser = ArgumentParser()
    parser.add_argument("input_file")
    parser.add_argument("-o", "--output", default="network_flow_diagram")
    args = parser.parse_args()

    if not os.path.exists(args.input_file):
        print(f"❌ Not found: {args.input_file}")
        sys.exit(1)

    gen = AzureNetworkDiagramGenerator(args.input_file, args.output)
    gen.run()


if __name__ == "__main__":
    main()
