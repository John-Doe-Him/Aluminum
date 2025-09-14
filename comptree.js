import http from "http";
import { createProxyServer } from "http-proxy";

export function startAluminumProxy(port = 8080) {
  const proxy = createProxyServer({});
  const server = http.createServer((req, res) => {
    // Proxy rule
    if (req.url.startsWith("/api")) {
      proxy.web(req, res, { target: "http://localhost:3000" });
      return;
    }
    res.writeHead(200);
    res.end("Aluminum internal server running");
  });

  server.listen(port, () => console.log(`Internal server on ${port}`));
}
