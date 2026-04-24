const express = require("express");
const driver = require("./db");
const cors = require("cors");

const app = express();

// ✅ Enable CORS (fixes your error)
app.use(cors());

// 🔹 Root route (test if server is running)
app.get("/", (req, res) => {
  res.send("API is running 🚀");
});

// 🔹 Get full graph data
app.get("/graph", async (req, res) => {
  const session = driver.session();

  try {
    const result = await session.run(`
      MATCH (c:CVE)-[r:AFFECTS]->(s:Software)
      RETURN c, r, s LIMIT 100
    `);

    const data = result.records.map(record => ({
      cve: record.get("c").properties,
      software: record.get("s").properties
    }));

    res.json(data);
  } catch (err) {
    console.error("Graph error:", err);
    res.status(500).send("Error fetching graph data");
  } finally {
    await session.close();
  }
});

// 🔹 Get critical vulnerabilities
app.get("/critical", async (req, res) => {
  const session = driver.session();

  try {
    const result = await session.run(`
      MATCH (c:CVE)
      WHERE c.severity = "Critical"
      RETURN c LIMIT 50
    `);

    const data = result.records.map(r => r.get("c").properties);

    res.json(data);
  } catch (err) {
    console.error("Critical error:", err);
    res.status(500).send("Error fetching critical CVEs");
  } finally {
    await session.close();
  }
});

// 🚀 Start server
const PORT = 4000;

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});