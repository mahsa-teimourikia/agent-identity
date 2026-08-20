import networkx as nx
def identity_graph(events):
    g=nx.MultiDiGraph()
    for e in events:
        a=e.get("actor",{}).get("id")
        r=e.get("resource")
        if a: g.add_node(a,kind=e.get("actor",{}).get("type","unknown"))
        if r:
            g.add_node(r,kind="resource")
            g.add_edge(a,r,event_type=e.get("event_type"),action=e.get("action"),trace_id=e.get("trace_id"))
        d=e.get("delegate")
        if a and d:
            g.add_node(d,kind="agent"); g.add_edge(a,d,event_type="delegation")
    return g
