import ForceGraph2D from "react-force-graph-2d";
import { useEffect, useState, useRef } from "react";

function App() {
  const [graph, setGraph] = useState({ nodes: [], links: [] });
  const [selected, setSelected] = useState(null);
  const [search, setSearch] = useState("");

  const fgRef = useRef();

  useEffect(() => {
    fetch("http://localhost:4000/graph")
      .then(res => res.json())
      .then(data => {
        const nodeSet = new Set();
        const nodes = [];
        const links = [];

        data.forEach(d => {
          if (d.cve && d.cve.id && !nodeSet.has(d.cve.id)) {
            nodes.push({
              id: d.cve.id,
              group: d.cve.severity || "cve",
              description: d.cve.description || "No description",
              score: d.cve.cvssScore || 0
            });
            nodeSet.add(d.cve.id);
          }

          if (d.software && d.software.name && !nodeSet.has(d.software.name)) {
            nodes.push({
              id: d.software.name,
              group: "software"
            });
            nodeSet.add(d.software.name);
          }

          if (d.cve && d.software) {
            links.push({
              source: d.cve.id,
              target: d.software.name
            });
          }
        });

        setGraph({ nodes, links });
      })
      .catch(err => console.error("Fetch error:", err));
  }, []);

  // 🔍 Filter
  const filteredNodes = graph.nodes.filter(n =>
    n.id.toLowerCase().includes(search.toLowerCase())
  );

  const filteredLinks = graph.links.filter(link =>
    filteredNodes.find(n => n.id === link.source) &&
    filteredNodes.find(n => n.id === link.target)
  );

  // 📊 Stats
  const criticalCount = graph.nodes.filter(n => n.group === "Critical").length;

  return (
    <div style={{ height: "100vh", background: "#0f172a", color: "white" }}>

      {/* HEADER */}
      <div style={{ padding: 10 }}>
        <h2>Cyber Threat Intelligence Dashboard</h2>
        <p>🔴 Critical Vulnerabilities: {criticalCount}</p>
      </div>

      {/* SEARCH */}
      <div style={{ paddingLeft: 10 }}>
        <input
          placeholder="Search CVE..."
          onChange={e => setSearch(e.target.value)}
          style={{
            padding: 8,
            borderRadius: 5,
            border: "none"
          }}
        />
      </div>

      {/* GRAPH */}
      <ForceGraph2D
        ref={fgRef}
        graphData={{ nodes: filteredNodes, links: filteredLinks }}

        nodeColor={node => {
          if (node.group === "Critical") return "red";
          if (node.group === "High") return "orange";
          if (node.group === "Medium") return "yellow";
          if (node.group === "Low") return "green";
          return "cyan";
        }}

        nodeLabel={node => `${node.id}\nSeverity: ${node.group}`}

        nodeRelSize={6}

        linkColor={() => "#888"}

        backgroundColor="#0f172a"

        onNodeClick={(node) => {
          setSelected(node); // ✅ clean click behavior
        }}

        d3Force="charge"
        d3ForceConfig={{
          charge: { strength: -120 },
          link: { distance: 80 }
        }}
      />

      {/* DETAILS PANEL */}
      {selected && (
        <div style={{
          position: "absolute",
          right: 10,
          top: 100,
          width: 300,
          background: "#1e293b",
          padding: 15,
          borderRadius: 10
        }}>
          <h3>{selected.id}</h3>
          <p><b>Severity:</b> {selected.group}</p>
          <p><b>Score:</b> {selected.score}</p>
          <p>{selected.description}</p>
        </div>
      )}

    </div>
  );
}

export default App;