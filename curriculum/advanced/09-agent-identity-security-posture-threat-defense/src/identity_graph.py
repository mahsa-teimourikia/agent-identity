import networkx as nx
class IdentityGraph:
    def __init__(self): self.g=nx.DiGraph()
    def add_node(self,node,kind,**attrs): self.g.add_node(node,kind=kind,**attrs)
    def add_edge(self,a,b,relation,risk=1,**attrs): self.g.add_edge(a,b,relation=relation,risk=risk,**attrs)
    def paths(self,source,target,cutoff=6): return list(nx.all_simple_paths(self.g,source,target,cutoff=cutoff))
    def blast_radius(self,source): return set(nx.descendants(self.g,source))
    def choke_points(self):
        return sorted(nx.betweenness_centrality(self.g).items(),key=lambda x:x[1],reverse=True)
