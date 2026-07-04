require("dotenv").config();
const express = require("express");
const cors = require("cors");
const http = require("http");
const path = require("path");

const storageRoutes = require("./storageRoutes");
const { makeRaceServer, setDb } = require("./race");
const db = require("./db");

const app = express();
app.use(cors({
  origin: ["https://pandatype.org", "https://www.pandatype.org", "http://localhost:3000"],
  credentials: true
}));
app.use(express.json({ limit: "10mb" }));

app.use("/api", storageRoutes);

app.get("/health", (req, res) => {
  res.json({ ok: true, time: Date.now() });
});

// Serve static files from public/
app.use(express.static(path.join(__dirname, "..", "public")));

// Catch-all: serve the SPA for all non-API routes
app.use((req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "zebra_type.html"));
});

const httpServer = http.createServer(app);
setDb(db);
makeRaceServer(httpServer);

const PORT = process.env.PORT || 3001;
httpServer.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
  console.log(`  Game:       http://localhost:${PORT}`);
  console.log(`  HTTP API:   http://localhost:${PORT}/api`);
  console.log(`  WebSocket:  ws://localhost:${PORT}/race`);
});
